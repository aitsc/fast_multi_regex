import logging
from fastapi import Request, FastAPI, HTTPException, Depends
from typing import Literal
import pickle
import os
import time
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .matcher import (
    MultiRegexMatcher,
    OneRegex,
    OneTarget,
    MultiRegexMatcherInfo,
    OneFindRegex,
)
from .utils import (
    load_matchers,
    DelayedFilesHandler,
)
from .api_types import (
    OneMatch,
    OneMatchMark,
    OneQuery,
    BodyMatch,
    RespMatch,
    RespInfo,
    BodyTargets,
    RespTargets,
    BodyFindExpression,
    RespFindExpression,
)


def file_processor(
    path: str, 
    opt: Literal['modified', 'created', 'deleted'],
    context: dict,
):
    matchers_folder: str = context['matchers_folder']
    matchers: dict[str, MultiRegexMatcher] = context['matchers']
    name = os.path.splitext(os.path.relpath(path, matchers_folder))[0]
    if opt == 'modified' or opt == 'created':
        with open(path, 'rb') as f:
            matchers[name] = pickle.load(f)
    elif opt == 'deleted':
        matchers.pop(name, None)
    logging.info(f'update matcher "{name}" {opt}')


matchers_folder = os.getenv('FAST_MULTI_REGEX_MATCHERS_FOLDER', 'data/matchers')
api_tokens = set(os.getenv('FAST_MULTI_REGEX_API_TOKENS', 'test').split(','))
matchers_api_update_delay = int(os.getenv('FAST_MULTI_REGEX_MATCHERS_API_UPDATE_DELAY', 3))
global_matchers: dict[str, MultiRegexMatcher] = {}


async def startup():
    global global_matchers
    global_matchers = load_matchers(matchers_folder)
    logging.info(f"init global_matchers: {list(global_matchers)}")
    DelayedFilesHandler(
        matchers_folder,
        file_handler=file_processor,
        delay=matchers_api_update_delay,
        context={
            'matchers_folder': matchers_folder,
            'matchers': global_matchers,
        },
    )


app = FastAPI()
app.add_event_handler("startup", startup)
security = HTTPBearer()


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials:
        token = credentials.credentials
        if token not in api_tokens:
            raise HTTPException(status_code=403, detail="Invalid or expired token")
    else:
        raise HTTPException(status_code=403, detail="Invalid authorization code")


@app.post(
    "/match",
    response_model=RespMatch,
    dependencies=[Depends(verify_token)],
    summary="使用 query 去快速匹配相应的正则库",
    description="使用 query 去快速匹配相应的正则库",
)
async def post_match(body: BodyMatch):
    start = time.time()
    result = []
    qs = body.qs if isinstance(body.qs, list) else [body.qs]
    
    for i, q in enumerate(qs):
        if q.db not in global_matchers:
            return RespMatch(message=f"qs{i}: db '{q.db}' not found", status=1)
        one_result: list[OneMatchMark] = []
        
        if q.method == 'all':
            matches = global_matchers[q.db].match_all(q.query, q.is_sort, q.detailed_level, q.match_top_n)
            if isinstance(matches, list):
                one_result += [OneMatchMark(mark=m) for m in matches]
            else:
                for mark, v in matches.items():
                    if isinstance(v, int):
                        one_result.append(OneMatchMark(mark=mark, match_count=v))
                    else:
                        one_result.append(OneMatchMark(mark=mark, matches=v, match_count=len(v)))
                        
        elif q.method == 'first':
            match = global_matchers[q.db].match_first(q.query)
            if match:
                one_result.append(OneMatchMark(mark=match[0], matches=[OneMatch(**match[1])]))
                
        elif q.method == 'strict':
            matches = global_matchers[q.db].match_strict(q.query, q.is_sort)
            for mark, v in matches.items():
                one_result.append(OneMatchMark(mark=mark, matches=v, match_count=len(v)))
                
        else:
            return RespMatch(message=f"qs{i}: method '{q.method}' not found", status=1)
        
        for om in one_result:
            if q.detailed_level == 1:
                om.matches = None
                om.match_count = None
            elif q.detailed_level == 2:
                om.matches = None
        result.append(one_result)
    return RespMatch(result=result, milliseconds=(time.time() - start) * 1000)


@app.get(
    "/info",
    response_model=RespInfo,
    dependencies=[Depends(verify_token)],
    summary="获取正则库信息",
    description="用于分析正则库是否正常，包括最近什么时候编译更新过",
)
async def get_info(db: str = 'default'):
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
    if body.db in global_matchers:
        targets = [global_matchers[body.db].get_target(mark) for mark in body.marks]
        return RespTargets(result=targets)
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
