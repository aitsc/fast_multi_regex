from pydantic import BaseModel, Field
from typing import Union, Literal, Optional
from .matcher import (
    MultiRegexMatcherInfo,
    OneTarget,
    OneFindRegex,
)


class OneTargetExt(OneTarget):
    '''扩展的一组正则表达式，增加了一些额外信息'''
    meta: Optional[dict] = Field(None, description='meta 信息，如果配置提供的话')


class OneMatch(BaseModel):
    '''一个正则的匹配结果'''
    start: int = Field(..., ge=0, description='匹配开始位置, 从 0 开始')
    end: int = Field(..., ge=0, description='匹配结束位置, 从 0 开始')
    match_no: int = Field(..., ge=0, description='总共第几次匹配到的，从0开始')
    mark_regex_no: int = Field(..., ge=0, description='OneTarget.regexs 中的第几个正则匹配到的，从0开始')


class OneMatchMark(BaseModel):
    '''一个正则组（对应一个mark）的匹配结果'''
    mark: str = Field(..., description='匹配到的正则组')
    matches: Optional[list[OneMatch]] = Field(None, description='匹配到具体正则的详细信息')
    match_count: Optional[int] = Field(None, description='停止匹配前匹配到的正则次数')
    meta: Optional[dict] = Field(None, description='meta 信息，如果配置提供的话')


class OneQuery(BaseModel):
    '''一个待匹配的字符串和匹配方法'''
    query: str = Field(..., description='待匹配的字符串')
    db: str = Field('default', description='匹配的正则库 name，一般是相对于 matchers_folder 的pkl路径(无后缀名)')
    method: Literal['first', 'all', 'strict'] = Field('strict', description='匹配方法，first: 只返回第一个匹配，all: 返回所有匹配，strict: 严格匹配')
    is_sort: bool = Field(True, description='是否按照正则库中出现顺序返回，适用于 method=all/strict')
    detailed_level: Literal[1, 2, 3] = Field(2, description='1: 只返回 mark, 2: 返回 mark 和出现次数, 3: 返回详细 OneMatch')
    match_top_n: int = Field(0, description='匹配元素次数限制, 小于等于 0 代表不限制，适用于 method=all')
    allowed_return_meta_keys: Optional[list[str]] = Field(None, description='允许返回的 meta 的根 key 列表，None 代表全部返回')


class RespGeneral(BaseModel):
    '''通用返回信息'''
    message: str = Field('success', description='返回信息')
    status: Optional[int] = Field(0, description='状态码')


class BodyMatch(BaseModel):
    '''match 接口请求'''
    qs: Union[list[OneQuery], OneQuery] = Field(..., description='待匹配的字符串信息列表')


class RespMatch(RespGeneral):
    '''match 接口返回信息'''
    result: list[list[OneMatchMark]] = Field([], description='匹配结果, 就1个OneQuery还搜索不到的话会返回 [[]]')
    milliseconds: float = Field(-1, description='处理时间，单位毫秒')


class RespInfo(RespGeneral):
    '''info 接口返回信息'''
    result: Optional[MultiRegexMatcherInfo] = Field(None, description='正则库信息')


class BodyTargets(BaseModel):
    '''get_targets 接口请求'''
    marks: list[str] = Field(..., description='待查询的正则组mark')
    db: str = Field('default', description='正则库 name')


class RespTargets(RespGeneral):
    '''get_targets 接口返回信息'''
    result: Optional[list[Optional[OneTargetExt]]] = Field(None, description='正则组信息列表, None 代表未找到')


class BodyFindExpression(BaseModel):
    '''find_expression 接口请求'''
    s: str = Field(..., description='待匹配的字符串')
    exact_match: bool = Field(False, description='是否精确匹配')
    top_n: Optional[int] = Field(10, description='返回前几个, 小于等于 0 代表不限制')
    allow_flag: int = Field(-1, description='允许的 flag')
    prohibited_flag: int = Field(0, description='禁止的 flag')
    db: str = Field('default', description='正则库 name')


class RespFindExpression(RespGeneral):
    '''find_expression 接口返回信息'''
    result: Optional[list[OneFindRegex]] = Field(None, description='匹配到的正则组信息列表')
