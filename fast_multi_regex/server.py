import argparse
import os
import uvicorn
import multiprocessing
from .utils import update_matchers_folder


log_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "generic": {
            "format": "%(asctime)s %(levelname)s [%(process)d] %(message)s",
            "datefmt": "[%Y-%m-%d %H:%M:%S]",
            "class": "logging.Formatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "generic",
            "stream": "ext://sys.stderr",
        },
    },
    "loggers": {
        "root": {
            "level": "INFO",
            "handlers": ["console"],
        },
        "uvicorn": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
            "qualname": "uvicorn",
        },
    },
}


def app_server():
    parser = argparse.ArgumentParser(
        description="fast_multi_regex server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--api_tokens", type=str, default="test", help="API token，多个用英文逗号分隔")
    parser.add_argument("--port", type=int, default=8000, help="端口")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="主机")
    parser.add_argument("--workers", type=int, default=1, help="进程数量")
    parser.add_argument("--log_level", type=str, default="info", help="日志级别, 例如: debug, info, warning, error, critical")
    parser.add_argument("--log_config", type=str, default="", help="日志配置文件路径, 为空则使用默认配置")
    parser.add_argument("--matchers_folder", type=str, default="data/matchers", help="匹配器保存的文件夹, 没有则自动创建")
    parser.add_argument("--matchers_config_folder", type=str, default="data/matchers_config", help="匹配器配置文件夹，将自动把配置文件转换为匹配器, 没有则自动创建")
    parser.add_argument("--matchers_api_update_delay", type=int, default=3, help="API 进程读取更新匹配器的延迟（秒），防止频繁加载")
    parser.add_argument("--matchers_file_update_delay", type=int, default=10, help="解析匹配器配置的进程的解析延迟（秒），配置文件这么多秒后不再修改才会更新到匹配器文件夹")
    args = parser.parse_args()
    
    p = multiprocessing.Process(target=update_matchers_folder, kwargs={
        'matchers_folder': args.matchers_folder,
        'matchers_config_folder': args.matchers_config_folder,
        'delay': args.matchers_file_update_delay,
        'blocking': True,
    })
    p.daemon = True
    p.start()
    
    os.environ['FAST_MULTI_REGEX_MATCHERS_FOLDER'] = args.matchers_folder
    os.environ['FAST_MULTI_REGEX_API_TOKENS'] = args.api_tokens
    os.environ['FAST_MULTI_REGEX_MATCHERS_API_UPDATE_DELAY'] = str(args.matchers_api_update_delay)
    uvicorn.run(
        "fast_multi_regex:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
        log_config=args.log_config or log_config,
    )


if __name__ == "__main__":
    app_server()
