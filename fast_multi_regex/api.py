import logging
from fastapi import FastAPI, HTTPException, Depends, Response
from typing import Literal, Optional, Union
import pickle
import os
import time
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from prometheus_client import Gauge, generate_latest, Counter
from .matcher import (
    MultiRegexMatcher,
)
from .utils import (
    load_matchers_and_metadata,
    DelayedFilesHandler,
    model_to_dict,
    get_model_info,
    get_process_index,
)
from .api_types import (
    BodyMatch,
    RespMatch,
    RespInfo,
    BodyTargets,
    RespTargets,
    BodyFindExpression,
    RespFindExpression,
)


api_tokens = set(os.getenv('FAST_MULTI_REGEX_API_TOKENS', 'test').split(','))
matchers_folder = os.getenv('FAST_MULTI_REGEX_MATCHERS_FOLDER', 'data/matchers')
matchers_api_update_delay = int(os.getenv('FAST_MULTI_REGEX_MATCHERS_API_UPDATE_DELAY', 3))
matcher_logger = logging.getLogger('matcher')
process_index = get_process_index()
global_matchers: dict[str, MultiRegexMatcher] = {}
global_metadata: dict[str, dict[str, Optional[dict]]] = {}
global_metric_wrapper: dict[str, Union[Counter, Gauge]] = {  # 初始赋值的 key 不用 fmrs_ 开头，小心函数内新建的重复
    # api 接口
    'post_match': Counter('fmrs_api_post_match', 'post_match interface request times', ['process_index']).labels(process_index),
    'get_info': Counter('fmrs_api_get_info', 'get_info 接口请求次数', ['process_index']).labels(process_index),
    'post_targets': Counter('fmrs_api_post_targets', 'post_targets 接口请求次数', ['process_index']).labels(process_index),
    'post_find_expression': Counter('fmrs_api_post_find_expression', 'post_find_expression 接口请求次数', ['process_index']).labels(process_index),
    'get_metrics': Counter('fmrs_api_get_metrics', 'get_metrics 接口请求次数', ['process_index']).labels(process_index),
    # post_match 接口内
    'match_query': Counter('fmrs_match_query', 'match 查询的有效 query 总数', ['process_index']).labels(process_index),
    'match_hit_query': Counter('fmrs_match_hit_query', 'match 查询有 mark 返回的 query 总数', ['process_index']).labels(process_index),
    'match_hit_mark': Counter('fmrs_match_hit_mark', 'match 查询有 mark 返回的 mark 总数', ['process_index']).labels(process_index),
    'match_query_char': Counter('fmrs_match_query_char', 'match 查询的有效 query 总字符数', ['process_index']).labels(process_index),
}


def pkl_file_processor(
    path: str, 
    opt: Literal['modified', 'created', 'deleted'],
    context: dict,
    *args,
    **kwargs,
):
    if not path or os.path.basename(path)[0] == '.':
        return
    file_extension = os.path.splitext(path)[1]
    if file_extension == '.pkl':
        name_info: dict[str, MultiRegexMatcher] = context['matchers']
        name_type = 'matcher'
    elif file_extension == '.meta_pkl':
        name_info: dict[str, dict[str, Optional[dict]]] = context['metadata']
        name_type = 'metadata'
    else:
        return
    
    matchers_folder: str = context['matchers_folder']
    name = os.path.splitext(os.path.relpath(path, matchers_folder))[0]
    if opt == 'modified' or opt == 'created':
        with open(path, 'rb') as f:
            name_info[name] = pickle.load(f)
    elif opt == 'deleted':
        name_info.pop(name, None)
        
    matcher_logger.info(f'update {name_type} "{name}" {opt}')


async def startup():
    global global_matchers, global_metadata
    global_matchers, global_metadata = load_matchers_and_metadata(matchers_folder)
    matcher_logger.info(f"init global_matchers: {list(global_matchers)}")
    DelayedFilesHandler(
        matchers_folder,
        file_handler=pkl_file_processor,
        delay=matchers_api_update_delay,
        context={
            'matchers_folder': matchers_folder,
            'matchers': global_matchers,
            'metadata': global_metadata,
        },
    )


app = FastAPI(
    title='fast-multi-regex',
    summary='A fast multi regex matcher',
    description='快速多正则和布尔表达式匹配，支持热更新正则库',
)
app.add_event_handler("startup", startup)
security = HTTPBearer()


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token not in api_tokens:
        raise HTTPException(status_code=403, detail="Invalid or expired token")


@app.post(
    "/match",
    response_model=RespMatch,
    dependencies=[Depends(verify_token)],
    summary="使用 query 去快速匹配相应的正则库",
    description="使用 query 去快速匹配相应的正则库",
)
async def post_match(body: BodyMatch):
    start = time.time()
    global_metric_wrapper['post_match'].inc()
    result = []
    qs = body.qs if isinstance(body.qs, list) else [body.qs]
    
    for i, q in enumerate(qs):
        if q.db not in global_matchers:
            return RespMatch(message=f"qs{i}: db '{q.db}' not found", status=1)
        one_result: list[dict] = []  # list[OneMatchMark]
                        
        if q.method == 'first':
            try:
                match = global_matchers[q.db].match_first(q.query)
            except BaseException as e:
                return RespMatch(message=f"qs{i}.first: {e}", status=2)
            if match:
                one_result.append({'mark': match[0], 'matches': [match[1]], 'match_count': 1})
        
        elif q.method == 'all':
            try:
                matches = global_matchers[q.db].match_all(q.query, q.is_sort, q.detailed_level, q.match_top_n)
            except BaseException as e:
                return RespMatch(message=f"qs{i}.all: {e}", status=3)
            if isinstance(matches, list):
                one_result += [{'mark': m} for m in matches]
            else:
                for mark, v in matches.items():
                    if isinstance(v, int):
                        one_result.append({'mark': mark, 'match_count': v})
                    else:
                        one_result.append({'mark': mark, 'matches': v, 'match_count': len(v)})
                
        elif q.method == 'strict':
            try:
                matches = global_matchers[q.db].match_strict(q.query, q.is_sort)
            except BaseException as e:
                return RespMatch(message=f"qs{i}.strict: {e}", status=4)
            for mark, v in matches.items():
                one_result.append({'mark': mark, 'matches': v, 'match_count': len(v)})
                
        else:
            return RespMatch(message=f"qs{i}: method '{q.method}' not found", status=5)
        
        db_metadata = global_metadata.get(q.db) or {}
        for om in one_result:
            om['meta'] = db_metadata.get(om['mark'])
            if om['meta'] and q.allowed_return_meta_keys:
                om['meta'] = {k: om['meta'][k] for k in q.allowed_return_meta_keys if k in om['meta']}
            if q.detailed_level == 1:
                om['matches'] = None
                om['match_count'] = None
            elif q.detailed_level == 2:
                om['matches'] = None
        result.append(one_result)
        
        if one_result:
            global_metric_wrapper['match_hit_query'].inc()
            global_metric_wrapper['match_hit_mark'].inc(len(one_result))
        global_metric_wrapper['match_query'].inc()
        global_metric_wrapper['match_query_char'].inc(len(q.query))
        
    return RespMatch(result=result, milliseconds=(time.time() - start) * 1000)


@app.get(
    "/info",
    response_model=RespInfo,
    dependencies=[Depends(verify_token)],
    summary="获取正则库信息",
    description="用于分析正则库是否正常，包括最近什么时候编译更新过",
)
async def get_info(db: str = 'default'):
    global_metric_wrapper['get_info'].inc()
    if db in global_matchers:
        info = global_matchers[db].info
        return RespInfo(result=info)
    else:
        return RespInfo(message=f"db '{db}' not found", status=1)


@app.post(
    "/get_targets",
    response_model=RespTargets,
    dependencies=[Depends(verify_token)],
    summary="获取正则组信息",
    description="可用于查询 match 返回的 mark 对应的具体正则组信息",
)
async def post_targets(body: BodyTargets):
    global_metric_wrapper['post_targets'].inc()
    if body.db in global_matchers:
        matcher = global_matchers[body.db]
        db_metadata = global_metadata.get(body.db) or {}
        ext_targets = []
        for mark in body.marks:
            target = matcher.get_target(mark)
            if target is None:
                ext_targets.append(None)
            else:
                ext_targets.append({
                    **model_to_dict(target),
                    'meta': db_metadata.get(mark),
                })
        return RespTargets(result=ext_targets)
    else:
        return RespTargets(message=f"db '{body.db}' not found", status=1)


@app.post(
    "/find_expression",
    response_model=RespFindExpression,
    dependencies=[Depends(verify_token)],
    summary="从正则库中查找正则表达式",
    description="可用于查找一些正则是否存在，帮助增删改相关正则",
)
async def post_find_expression(body: BodyFindExpression):
    global_metric_wrapper['post_find_expression'].inc()
    if body.db in global_matchers:
        result = global_matchers[body.db].find_expression(
            s=body.s, 
            exact_match=body.exact_match, 
            top_n=body.top_n,
            allow_flag=body.allow_flag,
            prohibited_flag=body.prohibited_flag,
        )
        return RespFindExpression(result=result)
    else:
        return RespFindExpression(message=f"db '{body.db}' not found", status=1)


@app.get(
    '/metrics',
    dependencies=[Depends(verify_token)],
    summary='Prometheus metrics',
    description='Prometheus metrics',
)
async def get_metrics():
    global_metric_wrapper['get_metrics'].inc()
    if 'fmrs_matchers_num' not in global_metric_wrapper:
        global_metric_wrapper['fmrs_matchers_num'] = Gauge('fmrs_matchers_num', '匹配器/正则库的数量', ['process_index']).labels(process_index)
    global_metric_wrapper['fmrs_matchers_num'].set(len(global_matchers))
    
    # from MultiRegexMatcherInfo
    total_matchers_metrics: dict[str, Union[int, float]] = {}
    max_matchers_metrics: dict[str, Union[int, float]] = {}
    min_matchers_metrics: dict[str, Union[int, float]] = {}
    matchers_metrics_description: dict[str, str] = {}
    
    for _, matcher in global_matchers.items():
        for metric, info in get_model_info(matcher.info).items():
            value = info['value']
            if not isinstance(value, (int, float, bool)):
                continue
            matchers_metrics_description[metric] = info['description']
            total_matchers_metrics.setdefault(metric, 0)
            if isinstance(value, bool):
                total_matchers_metrics[metric] += 1 if value else 0
            else:
                total_matchers_metrics[metric] += value
                if metric in max_matchers_metrics:
                    max_matchers_metrics[metric] = max(max_matchers_metrics[metric], value)
                else:
                    max_matchers_metrics[metric] = value
                if metric in min_matchers_metrics:
                    min_matchers_metrics[metric] = min(min_matchers_metrics[metric], value)
                else:
                    min_matchers_metrics[metric] = value
                    
    for metric, value in total_matchers_metrics.items():
        name = f'fmrs_matchers_{metric}_total'
        description = matchers_metrics_description[metric]
        if name not in global_metric_wrapper:
            global_metric_wrapper[name] = Gauge(name, f"总数: {description}", ['process_index']).labels(process_index)
        global_metric_wrapper[name].set(value)
        
    for metric, value in max_matchers_metrics.items():
        name = f'fmrs_matchers_{metric}_max'
        description = matchers_metrics_description[metric]
        if name not in global_metric_wrapper:
            global_metric_wrapper[name] = Gauge(name, f"最大值: {description}", ['process_index']).labels(process_index)
        global_metric_wrapper[name].set(value)
        
    for metric, value in min_matchers_metrics.items():
        name = f'fmrs_matchers_{metric}_min'
        description = matchers_metrics_description[metric]
        if name not in global_metric_wrapper:
            global_metric_wrapper[name] = Gauge(name, f"最小值: {description}", ['process_index']).labels(process_index)
        global_metric_wrapper[name].set(value)

    return Response(generate_latest(), media_type='text/plain')
