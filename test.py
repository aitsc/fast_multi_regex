from fast_multi_regex import *
import time
import pickle
import hyperscan
import json
from pprint import pprint
import uvicorn


def test_matcher():
    # 创建一个 MultiRegexMatcher 实例
    mr = MultiRegexMatcher()
    # 传入一组正则表达式
    mark_expressions = {
        'test': r"(test|demo)[0-9]{2,4}",
        'test1': r"\b(test[123]+)\b",
        'test2': r"(test|trial|demo)[a-zA-Z]{2,6}\d+",
        'test3': r"\b\d{3}test\b",
        'test4': r"test\d{1,3}demo",
        'test5': r' *abcd',
        'test6': "\n  \"institution\": \".+?大学\"",
        'test7': "\n  \"institution\": \"清华大学\"",
    }
    expressions = list(mark_expressions.values()) * 100
    mark_expressions.update({f'test_auto_{i}': f'{exp} {i}' for i, exp in enumerate(expressions)})
    mark_expressions.update({f'test_auto2_{i}': f'abc23wrfsda' for i in range(100)})
    mark_expressions['test8'] = "\n  \"institution\": \"清华.+大学2\""
    targets = [OneTarget(mark=mark, regexs=[OneRegex(
        expression=exp,
        flag=0,
    )]) for mark, exp in mark_expressions.items()]
    targets.append(OneTarget(
        mark='test9',
        regexs=[
            OneRegex(expression=r"demo2 abcd"),
            OneRegex(expression="\n  \"institution\": \"清华.+大学2\""),
        ],
        min_regex_count=0,
        max_regex_count=0,
    ))
    targets.append(OneTarget(
        mark='test10',
        regexs=[
            OneRegex(expression=r"demo2abcd"),
            OneRegex(expression="\n  \"institution\": \"清华.+大学2\""),
        ],
        bool_expr='r1 & ~r0',
    ))
    
    start = time.time()
    mr.compile(targets)
    
    print('before pickle.dump', time.time())
    with open('data/matchers/test.pkl', 'wb') as file:
        pickle.dump(mr, file)
    print('after pickle.dump', time.time())
    with open('data/matchers/test.pkl', 'rb') as file:
        mr: MultiRegexMatcher = pickle.load(file)
    print('after pickle.load', time.time())
    
    print(mr._mark_target_no['test'])
    mr.exchange_targets([(0, 10)], mark_is_no=True, lazy_compilation=True)
    mr.update_targets([
        OneTarget(
            mark='test11',
            regexs=[
                OneRegex(expression=r"demo2abcd"),
                OneRegex(expression="\n  \"instittion\": \"清华.+大学2\""),
            ],
            bool_expr='~r1 & ~r0',
        ),
        OneTarget(mark='test12', regexs=[
            OneRegex(expression=r"test", min_match_count=1, max_match_count=3, flag=0),
        ]),
        OneTarget(mark='test13', regexs=[
            OneRegex(expression=r"test", flag=hyperscan.HS_FLAG_SINGLEMATCH|hyperscan.HS_FLAG_QUIET),
        ]),
        OneTarget(mark='test14', regexs=[
            OneRegex(expression="test13.0 & test13.0", flag=hyperscan.HS_FLAG_SINGLEMATCH|hyperscan.HS_FLAG_COMBINATION),
        ]),
    ])
    print(f"Compilation time ({len(mark_expressions)}): {time.time() - start:f}s")
    print(mr._mark_target_no['test'])
    print()
    
    # 测试字符串
    test_string = json.dumps({
        "body": {"institution": "清华asdfsdafsdafasdf大学2"},
        "test": "demo1",
        "test2": " demo2 abcd",
        "test3": " demo3 abcd",
    }, ensure_ascii=False, indent=1)
    # print(test_string)
    # test_string = ' abcd abcd'
    
    # 获取第一个匹配的标记
    start = time.time()
    print('match_all:', mr.match_all(test_string, detailed_level=3, match_top_n=0, is_sort=False))
    for i in range(1000):
        mr.match_all(f"{test_string}{i}")
    print(f"All match time: {time.time() - start:f}s")
    print()
    
    start = time.time()
    print('match_first:', mr.match_first(test_string))
    for i in range(1000):
        mr.match_first(f"{test_string}{i}")
    print(f"First match time: {time.time() - start:f}s")
    print()
    
    matches = mr.match_strict(test_string, is_sort=False)
    print('match_strict:', list(matches))
    print([k for k, v in sorted(matches.items(), key=lambda x: x[1][0]['match_no'] if x[1] else float('inf'))])
    print(mr.get_target('test11'))
    for i in range(1000):
        mr.match_strict(f"{test_string}{i}_s")
    print(f"Match strict time: {time.time() - start:f}s")
    print()
    
    pprint(dict(mr.info))
    pprint(mr.find_expression(r"清华.+大学2", allow_flag=8, top_n=1))
    


def test_utils():
    # print(load_matchers('.'))
    # DelayedFilesHandler('data/matchers')
    # input('press any key to exit\n')
    ret = sync_request(
        url='http://127.0.0.1:8000/info',
        token='test',
        body={'db': 'test'},
        method='get',
    )
    print(ret)


def test_api():
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
    uvicorn.run(
        "fast_multi_regex:app",
        host="0.0.0.0",
        port=8000,
        workers=2,
        log_config=log_config,
    )


def test_update():
    matchers_folder = 'data/matchers'
    matchers_config_folder = 'data/matchers_config'
    matchers = load_matchers(matchers_folder)
    print('init matchers:', list(matchers))
    DelayedFilesHandler(
        matchers_config_folder, 
        file_handler=file_processor_matchers_update,
        context={
            'matchers_folder': matchers_folder,
            'matchers_config_folder': matchers_config_folder,
            'matchers': matchers,
        },
        delay=3,
    )
    input('Press Enter to exit\n')


if __name__ == '__main__':
    # test_matcher()
    # test_utils()
    # test_api()
    # test_update()
    app_server()
