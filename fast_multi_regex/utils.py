import pickle
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
import atexit
import threading
from typing import Literal, Callable, Any, Optional, Union
from pydantic import BaseModel
import aiohttp
import logging
import asyncio
import requests
import time
import json
from .matcher import MultiRegexMatcher


def load_matchers(folder: str) -> dict[str, MultiRegexMatcher]:
    """递归加载文件夹中的所有 MultiRegexMatcher pkl 文件

    Args:
        folder (str): 主文件夹路径

    Returns:
        dict[str, MultiRegexMatcher]: 加载结果，str 为相对于 folder 的路径
    """
    matchers = {}
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith('.pkl') and file[0] != '.':
                path = os.path.join(root, file)
                relative_path = os.path.relpath(path, folder)
                name = os.path.splitext(relative_path)[0]
                with open(path, 'rb') as f:
                    matchers[name] = pickle.load(f)
    return matchers


class DelayedFilesHandler(FileSystemEventHandler):
    def __init__(
        self, 
        folder: str, 
        file_handler: Callable[
            [str, Literal['modified', 'created', 'deleted'], Any],
            Any,
        ] = lambda p, o: f'event: {p}, {o}',
        context: Any = None,
        delay: float = 3, 
    ):
        """延迟处理文件变化事件，使用多线程实现延迟，不适合大量文件变化

        Args:
            folder (str): 监听的文件夹路径
            file_handler (Callable[ [str, Literal['modified', 'created', 'deleted'], Any], Any, ], optional): 处理文件变化事件的函数, 输入 (path, opt, context), 输出 str (如果不为空用于print)
            context (Any, optional): 传递给 file_handler 的额外参数
            delay (float, optional): 延迟处理时间, 单位秒
        """
        assert os.path.isdir(folder), f"{folder} is not a directory"
        assert file_handler, "file_handler is required"
        self.folder = folder
        self.delay = delay
        self.file_handler = file_handler
        self.context = context
        self.timers: dict[str, threading.Timer] = {}  # 用字典存储文件和对应的定时器
        self.observer = Observer()
        self.observer.schedule(self, path=self.folder, recursive=True)
        self.observer.start()
        atexit.register(self.observer.stop)

    def reset_timer(self, path, opt):
        if path in self.timers:
            self.timers[path].cancel()  # 取消已存在的定时器
        self.timers[path] = threading.Timer(self.delay, self.process_event, [path, opt])
        self.timers[path].start()

    def process_event(self, path, opt):
        try:
            out = self.file_handler(path, opt, self.context)
            if out:
                print(out)
        except BaseException as e:
            print(f"DelayedFilesHandler process_event: {e}")
        finally:
            del self.timers[path]  # 处理完成后，从字典中删除定时器

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.reset_timer(event.src_path, 'modified')

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.reset_timer(event.src_path, 'created')

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.reset_timer(event.dest_path, 'created')
        self.reset_timer(event.src_path, 'deleted')

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self.reset_timer(event.src_path, 'deleted')
    
    def join(self):
        self.observer.join()


def file_processor_matchers_update(
    path: str, 
    opt: Literal['modified', 'created', 'deleted'],
    context: dict,
) -> Optional[str]:
    """利用配置文件更新 matchers 文件夹中的 matcher，配合 DelayedFilesHandler 实时监控使用

    Args:
        path (str): 发生变动的配置文件路径
        opt (Literal['modified', 'created', 'deleted']): 变动类型
        context (dict): 额外参数
            matchers_folder (str): matcher 文件夹路径
            matchers_config_folder (str): matcher 配置文件夹路径
            matchers (dict[str, MultiRegexMatcher]): matcher 字典

    Returns:
        str: 输出信息
    """
    if not (path.endswith('.json') and path[-1] != '.'):
        return
    matchers_folder: str = context['matchers_folder']
    matchers_config_folder: str = context['matchers_config_folder']
    matchers: dict[str, MultiRegexMatcher] = context['matchers']
    name = os.path.splitext(os.path.relpath(path, matchers_config_folder))[0]
    pkl_path = os.path.join(matchers_folder, f'{name}.pkl')
    success = False
    if opt == 'modified' or opt == 'created':
        with open(path, 'r', encoding='utf-8') as f:
            config: dict = json.load(f)
        if not config.get('targets'):
            return None
        cache_size = config.get('cache_size', 128)
        literal = config.get('literal', False)
        if name in matchers:
            success |= matchers[name].compile(config['targets'], literal=literal)
            if cache_size != matchers[name].info.cache_size:
                matchers[name].reset_cache(cache_size)
                success = True
        else:
            matchers[name] = MultiRegexMatcher(cache_size)
            matchers[name].compile(config['targets'], literal=literal)
            success = True
        if success:
            os.makedirs(os.path.dirname(pkl_path), exist_ok=True)
            with open(pkl_path, 'wb') as f:
                pickle.dump(matchers[name], f)
    elif opt == 'deleted':
        matchers.pop(name, None)
        if os.path.exists(pkl_path):
            os.remove(pkl_path)
            success = True
    if success:
        return f'file_processor_matchers_update: "{name}" {opt}'


def update_matchers_folder(
    matchers_folder: str,
    matchers_config_folder: str,
    delay: int = 30,
    create_folder: bool = True,
    blocking: bool = False,
) -> dict[str, MultiRegexMatcher]:
    """初始化 matchers 文件夹，创建 DelayedFilesHandler 监控配置文件夹, 根据配置变动实时更新 matchers 文件夹

    Args:
        matchers_folder (str): 匹配器保存的文件夹
        matchers_config_folder (str): 匹配器配置文件夹，将自动把配置文件转换为匹配器
        delay (int, optional): 配置文件这么多秒后不再修改才会更新到匹配器文件夹
        create_folder (bool, optional): 是否自动创建文件夹
        blocking (bool, optional): 是否阻塞

    Returns:
        dict[str, MultiRegexMatcher]: 加载的 matchers
    """
    if create_folder:
        os.makedirs(matchers_folder, exist_ok=True)
        os.makedirs(matchers_config_folder, exist_ok=True)
    matchers = load_matchers(matchers_folder)
    print('file_processor_matchers_update: init matchers:', list(matchers))
    obj = DelayedFilesHandler(
        matchers_config_folder, 
        file_handler=file_processor_matchers_update,
        context={
            'matchers_folder': matchers_folder,
            'matchers_config_folder': matchers_config_folder,
            'matchers': matchers,
        },
        delay=delay,
    )
    if blocking:
        obj.join()
    return matchers


async def async_request(
    url: Optional[str] = None,
    headers: Optional[dict] = None,
    body: Union[dict, BaseModel, None] = None,
    token: Optional[str] = None,
    try_times: int = 2,
    try_sleep: Union[float, int] = 1,
    method: Literal['get', 'post'] = 'post',
    timeout: Union[float, int] = None,
    **kwargs,
) -> dict:
    """异步请求

    Args:
        url (Optional[str], optional): 请求的 url
        headers (Optional[dict], optional): 请求头
        body (Union[dict, BaseModel, None], optional): 请求体
        token (Optional[str], optional): token，自动添加到 headers
        try_times (int, optional): 尝试次数
        try_sleep (Union[float, int], optional): 尝试间隔秒
        method (Literal['get', 'post'], optional): 请求方法
        timeout (Union[float, int], optional): 超时时间
        kwargs (dict): 其他 session 支持的参数

    Returns:
        dict: 请求结果
            message (str): 返回信息
            status (int): 状态码
    """
    body = body if isinstance(body, (dict, type(None))) else dict(body)
    if token:
        if not headers:
            headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {token}'
    for i in range(try_times):
        try:
            async with aiohttp.ClientSession() as session:
                timeout_ = aiohttp.ClientTimeout(total=timeout)
                if method == 'get':
                    req = session.get(url, headers=headers, params=body, timeout=timeout_, **kwargs)
                else:
                    req = session.post(url, headers=headers, json=body, timeout=timeout_, **kwargs)
                async with req as res:
                    if res.status == 200:
                        ret = await res.json()
                    else:
                        ret = {'message': (await res.text()), 'status': res.status}
                    return ret
        except BaseException as e:
            logging.warning(f'{url} post failed ({i+1}/{try_times}): {e}')
            if i + 1 < try_times:
                await asyncio.sleep(try_sleep)
            else:
                return {'message': str(e), 'status': -1}


def sync_request(
    url: str = None,
    headers: Optional[dict] = None,
    body: Union[dict, BaseModel, None] = None,
    token: Optional[str] = None,
    try_times: int = 2,
    try_sleep: Union[float, int] = 1,
    method: Literal['get', 'post'] = 'post',
    **kwargs,
) -> dict:
    """同步请求

    Args:
        url (Optional[str], optional): 请求的 url
        headers (Optional[dict], optional): 请求头
        body (Union[dict, BaseModel, None], optional): 请求体
        token (Optional[str], optional): token，自动添加到 headers
        try_times (int, optional): 尝试次数
        try_sleep (Union[float, int], optional): 尝试间隔秒
        method (Literal['get', 'post'], optional): 请求方法
        kwargs (dict): 其他 session 支持的参数，例如 timeout

    Returns:
        dict: 请求结果
            message (str): 返回信息
            status (int): 状态码
    """
    body = body if isinstance(body, (dict, type(None))) else dict(body)
    if token:
        if not headers:
            headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {token}'
    for i in range(try_times):
        try:
            if method == 'get':
                res = requests.get(url, headers=headers, params=body, **kwargs)
            else:
                res = requests.post(url, headers=headers, json=body, **kwargs)
            if res.status_code == 200:
                ret = res.json()
            else:
                ret = {'message': res.text, 'status': res.status_code}
            return ret
        except BaseException as e:
            logging.warning(f'{url} post failed ({i+1}/{try_times}): {e}')
            if i + 1 < try_times:
                time.sleep(try_sleep)
            else:
                return {'message': str(e), 'status': -1}
