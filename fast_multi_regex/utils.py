import pickle
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
import atexit
import threading
from typing import Literal, Callable, Any, Optional, Union, TypeVar
from pydantic import BaseModel
import aiohttp
import logging
import asyncio
import requests
import psutil
import time
import json
import yaml
import toml
from jsoncomment import JsonComment
from logging.handlers import RotatingFileHandler
from .matcher import MultiRegexMatcher, FlagExt, OneRegex
from .api_types import OneTargetExt


T = TypeVar('T')


def model_to_dict(model: Optional[Union[BaseModel, dict]], **kwargs) -> dict:
    """
    Convert a Pydantic model to a dictionary, compatible with both Pydantic 1.x and 2.x.
    """
    if isinstance(model, (dict, type(None))):
        return model
    try:
        # Try using Pydantic 2.x method
        return model.model_dump(**kwargs)
    except AttributeError:
        # Fallback to Pydantic 1.x method
        return model.dict(**kwargs)


def setup_logger(name, log_file, level=logging.INFO, max_bytes=10*1024*1024, backup_count=1):
    """
    Function to setup a logger with a specific name, log file, and log level.
    
    Args:
    - name (str): The name of the logger.
    - log_file (str): The file to which logs should be written.
    - level: The logging level. Default is logging.INFO.
    - max_bytes (int): The maximum file size in bytes before rotating. Default is 10MB.
    - backup_count (int): The number of backup files to keep. Default is 1.
    
    Returns:
    - logger: Configured logger object.
    """
    # Ensure the parent directory of log_file exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Create a custom logger
    logger = logging.getLogger(name)
    
    # Set the log level
    logger.setLevel(level)
    
    # Create handlers
    file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setLevel(level)
    
    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(file_handler)
    
    return logger


def load_config(path: str) -> Optional[dict]:
    """加载配置文件，支持 json, jsonc, yaml, yml, toml

    Args:
        path (str): 配置文件路径

    Returns:
        dict: 配置文件内容
    """
    if not os.path.exists(path):
        return None
    suffix = os.path.splitext(path)[1]
    if suffix not in {'.json', '.jsonc', '.yaml', '.yml', '.toml'}:
        return None
    config = {}
    with open(path, 'r', encoding='utf-8') as f:
        if suffix == '.json':
            config = json.load(f)
        elif suffix == '.jsonc':
            config = JsonComment().load(f)
        elif suffix in {'.yaml', '.yml'}:
            config = yaml.safe_load(f)
        elif suffix == '.toml':
            config = toml.load(f)
    assert isinstance(config, dict), f"config must be dict: {path}"
    return config


def get_model_info(model: Union[type[BaseModel], BaseModel]) -> dict[str, dict[str, Any]]:
    """获取 Pydantic 模型的字段信息
    
    Args:
        model (Union[type[BaseModel], BaseModel]): Pydantic 模型
        
    Returns:
        dict[str, dict[str, Any]]: 字段信息
    """
    info = {}
    try:
        fields = model.__fields__
    except AttributeError:
        fields = model.model_fields  # Pydantic 2.x 的字段属性
    
    for field_name, field_info in fields.items():
        if isinstance(model, BaseModel):
            value = getattr(model, field_name)
        else:
            value = ...
        description = field_info.field_info.description if hasattr(field_info, 'field_info') else field_info.description
        field_type = field_info.outer_type_ if hasattr(field_info, 'outer_type_') else field_info.annotation
        default_value = field_info.default if field_info.default is not None else None  # 默认值

        info[field_name] = {
            'value': value,  # 字段值, 如果是未实例化的 BaseModel 则为 ...
            'default_value': default_value,  # 默认值
            'description': description,  # 字段描述
            'type': field_type,  # 字段类型
        }
    return info


def get_process_index() -> int:
    """获取当前进程在父进程的子进程列表中的索引"""
    pid = os.getpid()
    parent_pid = os.getppid()
    parent = psutil.Process(parent_pid)
    children = parent.children()
    children.sort(key=lambda p: p.pid)
    for index, child in enumerate(children):
        if child.pid == pid:
            return index
    return -1


def load_matchers_and_metadata(folder: str) -> tuple[
    dict[str, MultiRegexMatcher],
    dict[str, dict[str, Optional[dict]]],
]:
    """递归加载文件夹中的所有 MultiRegexMatcher pkl 和 metadata 文件

    Args:
        folder (str): 主文件夹路径

    Returns:
        tuple[dict[str, MultiRegexMatcher], dict[str, dict[str, Optional[dict]]]]: matchers 和 metadata
            matchers: str 为相对于 folder 的路径
            metadata: 第一个 str 为相对于 folder 的路径，第二个 str 为 mark
    """
    matchers = {}
    metadata = {}
    for root, _, files in os.walk(folder):
        for file in files:
            if file[0] == '.':
                continue
            if file.endswith('.pkl') or file.endswith('.meta_pkl'):
                path = os.path.join(root, file)
                relative_path = os.path.relpath(path, folder)
                name = os.path.splitext(relative_path)[0]
                with open(path, 'rb') as f:
                    pkl = pickle.load(f)
                    if file.endswith('.pkl'):
                        matchers[name] = pkl
                    else:
                        metadata[name] = pkl
    return matchers, metadata


class DelayedFilesHandler(FileSystemEventHandler):
    def __init__(
        self, 
        folder: str, 
        file_handler: Callable[
            [str, Literal['modified', 'created', 'deleted'], T, logging.Logger],
            Any,
        ] = lambda p, o: f'event: {p}, {o}',
        context: T = None,
        delay: float = 3, 
        logger: Optional[logging.Logger] = None,
    ):
        """延迟处理文件变化事件，使用多线程实现延迟，不适合大量文件变化

        Args:
            folder (str): 监听的文件夹路径
            file_handler (Callable[ [str, Literal['modified', 'created', 'deleted'], Any], Any, ], optional): 处理文件变化事件的函数, 输入 (path, opt, context), 输出 str (如果不为空用于print)
            context (Any, optional): 传递给 file_handler 的额外参数
            delay (float, optional): 延迟处理时间, 单位秒
            logger (Optional[logging.Logger], optional): 日志记录器, 否则使用 print
        """
        assert os.path.isdir(folder), f"{folder} is not a directory"
        assert file_handler, "file_handler is required"
        self.logger = logger
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
            self.file_handler(path, opt, self.context, self.logger)
        except BaseException as e:
            text = f"DelayedFilesHandler process_event error: {e}"
            self.logger.error(text) if self.logger else print(text)
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


def set_auto_mark_for_targets(targets: list[dict]) -> list[dict]:
    """为 targets 中的每个正则组添加一个自动 mark, 原地修改

    Args:
        targets (list[dict]): 正则组列表, 来自配置文件，list[OneTargetExt]

    Returns:
        list[dict]: 添加了 mark 的正则组列表
    """
    if not targets:
        return targets
    for i, target in enumerate(targets):
        if not target.get('mark'):
            target['mark'] = f'auto_{i + 1}'
    return targets


def file_processor_matchers_update(
    path: str, 
    opt: Literal['modified', 'created', 'deleted'],
    context: dict,
    logger: Optional[logging.Logger] = None,
):
    """利用配置文件更新 matchers 文件夹中的 matcher 和 metadata，配合 DelayedFilesHandler 实时监控使用

    Args:
        path (str): 发生变动的配置文件路径，不能以 . 开头
        opt (Literal['modified', 'created', 'deleted']): 变动类型
        context (dict): 额外参数
            matchers_folder (str): matcher 文件夹路径
            matchers_config_folder (str): matcher 配置文件夹路径
            matchers (dict[str, MultiRegexMatcher]): matcher 字典
            metadata (dict[str, dict[str, Optional[dict]]]): metadata 字典
        logger (Optional[logging.Logger], optional): 日志记录器
    """
    if os.path.basename(path)[0] == '.':
        return
    suffix = os.path.splitext(path)[1]
    if suffix not in {'.json', '.jsonc', '.yaml', '.yml', '.toml'}:
        return
    matchers_folder: str = context['matchers_folder']
    matchers_config_folder: str = context['matchers_config_folder']
    matchers: dict[str, MultiRegexMatcher] = context['matchers']
    metadata: dict[str, dict[str, Optional[dict]]] = context['metadata']
    
    name = os.path.splitext(os.path.relpath(path, matchers_config_folder))[0]
    matcher_path = os.path.join(matchers_folder, f'{name}.pkl')
    db_metadata_path = os.path.join(matchers_folder, f'{name}.meta_pkl')
    actual_opts = []
    
    if opt == 'modified' or opt == 'created':
        config = load_config(path)
        if not config.get('targets'):
            return None
        set_auto_mark_for_targets(config['targets'])
        
        # load matcher
        cache_size = config.get('cache_size')
        literal = config.get('literal', False)
        success = False
        
        text = f'matcher "{name}" start compile ...'
        logger.info(text) if logger else print(text)
        
        if name in matchers:
            success |= matchers[name].compile(config['targets'], literal=literal)
            success |= matchers[name].reset_cache(cache_size, force=False)
        else:
            matchers[name] = MultiRegexMatcher(cache_size)
            matchers[name].compile(config['targets'], literal=literal)
            success = True
        if success:
            os.makedirs(os.path.dirname(matcher_path), exist_ok=True)
            with open(matcher_path, 'wb') as f:
                pickle.dump(matchers[name], f)
                actual_opts.append('dump matcher')
                
        # load db_metadata
        db_metadata = get_metadata_from_targets(config['targets'])
        if metadata.get(name) != db_metadata:
            metadata[name] = db_metadata
            os.makedirs(os.path.dirname(db_metadata_path), exist_ok=True)
            with open(db_metadata_path, 'wb') as f:
                pickle.dump(db_metadata, f)
                actual_opts.append('dump db_metadata')
        
    elif opt == 'deleted':
        matchers.pop(name, None)
        if os.path.exists(matcher_path):
            os.remove(matcher_path)
            actual_opts.append('del matcher')
        metadata.pop(name, None)
        if os.path.exists(db_metadata_path):
            os.remove(db_metadata_path)
            actual_opts.append('del db_metadata')
            
    if actual_opts:
        text = f'file_processor_matchers_update: "{name}" {opt}: {actual_opts}'
        logger.info(text) if logger else print(text)


matcher_config_example = {
    "cache_size": 128,  # 缓存大小
    "literal": False,  # 是否使用字面量匹配（正则当作普通字符匹配）
    "targets": [
        model_to_dict(OneTargetExt(
            mark="example",  # 正则组名称，不能重复
            regexs=[OneRegex(
                expression='例子',  # 正则
                flag_ext=FlagExt(),
            )],
        )),
    ]
}


def get_metadata_from_targets(ext_targets: list[dict]) -> dict[str, Optional[dict]]:
    """从 ext_targets 中获取 metadata, 出现相同的mark后出现的会覆盖前面的

    Args:
        ext_targets (list[dict]): 正则组列表, 来自配置文件，list[OneTargetExt]

    Returns:
        dict[str, Optional[dict]]: db_metadata, str 是 mark
    """
    db_metadata = {}
    for ext_target in ext_targets:
        if 'mark' not in ext_target or 'meta' not in ext_target:
            continue
        mark = ext_target['mark']
        meta = ext_target['meta']
        assert isinstance(mark, str), f"mark must be str: {ext_target}"
        assert isinstance(meta, dict) or meta is None, f"meta must be dict or None: {ext_target}"
        db_metadata[mark] = meta
    return db_metadata


def update_matchers_folder(
    matchers_folder: str,
    matchers_config_folder: str,
    delay: int = 30,
    create_folder: bool = True,
    blocking: bool = False,
    default_matcher_config: dict = matcher_config_example,
    logger: Optional[logging.Logger] = None,
) -> dict[str, MultiRegexMatcher]:
    """初始化 matchers 文件夹，创建 DelayedFilesHandler 监控配置文件夹, 根据配置变动实时更新 matchers 文件夹

    Args:
        matchers_folder (str): 匹配器保存的文件夹，包括 meta 信息
        matchers_config_folder (str): 匹配器配置文件夹，将自动把配置文件转换为匹配器
        delay (int, optional): 配置文件这么多秒后不再修改才会更新到匹配器文件夹
        create_folder (bool, optional): 是否自动创建文件夹
        blocking (bool, optional): 是否阻塞
        default_matcher_config (dict, optional): 默认配置, 当没有匹配器时且有这个变量会自动写入这个 default.json
        logger (Optional[logging.Logger], optional): 日志记录器, 否则使用 print

    Returns:
        dict[str, MultiRegexMatcher]: 加载的 matchers
    """
    if create_folder:
        os.makedirs(matchers_folder, exist_ok=True)
        os.makedirs(matchers_config_folder, exist_ok=True)
    matchers, metadata = load_matchers_and_metadata(matchers_folder)
    
    # 写入默认配置
    default_json = os.path.join(matchers_config_folder, 'default.json')
    if (
        not matchers and 
        default_matcher_config and 
        default_matcher_config.get('targets') and
        not os.path.exists(default_json)
    ):
        matchers['default'] = MultiRegexMatcher(default_matcher_config.get('cache_size'))
        matchers['default'].compile(
            default_matcher_config['targets'],
            literal=default_matcher_config.get('literal', False),
        )
        metadata['default'] = get_metadata_from_targets(default_matcher_config['targets'])
        
        with open(default_json, 'w', encoding='utf-8') as f:
            json.dump(default_matcher_config, f, ensure_ascii=False, indent=4)
        with open(os.path.join(matchers_folder, 'default.pkl'), 'wb') as f:
            pickle.dump(matchers['default'], f)
        with open(os.path.join(matchers_folder, 'default.meta_pkl'), 'wb') as f:
            pickle.dump(metadata['default'], f)
            
    # 遍历已有配置，更新 matchers，不会删除配置没有的多余 matchers
    context = {
        'matchers_folder': matchers_folder,
        'matchers_config_folder': matchers_config_folder,
        'matchers': matchers,
        'metadata': metadata,
    }
    for root, _, files in os.walk(matchers_config_folder):
        for file in files:
            path = os.path.join(root, file)
            file_processor_matchers_update(path, 'created', context, logger)
    if logger:
        logger.info(f'matchers_folder: init matchers: {list(matchers)}')
    else:
        print('matchers_folder: init matchers:', list(matchers))

    # 监控配置文件夹
    obj = DelayedFilesHandler(
        matchers_config_folder, 
        file_handler=file_processor_matchers_update,
        context=context,
        delay=delay,
        logger=logger,
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
    body = model_to_dict(body)
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
    body = model_to_dict(body)
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
