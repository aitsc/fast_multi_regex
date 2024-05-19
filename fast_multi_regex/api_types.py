from pydantic import BaseModel, Field
from typing import Union, Literal, Optional
from .matcher import (
    MultiRegexMatcherInfo,
    OneTarget,
    OneFindRegex,
)


class OneMatch(BaseModel):
    start: int = Field(..., ge=0, description='匹配开始位置, 从 0 开始')
    end: int = Field(..., ge=0, description='匹配结束位置, 从 0 开始')
    match_no: int = Field(..., ge=0, description='总共第几次匹配到的，从0开始')
    mark_regex_no: int = Field(..., ge=0, description='OneTarget.regexs 中的第几个正则匹配到的，从0开始')


class OneMatchMark(BaseModel):
    mark: str = Field(..., description='匹配到的正则组')
    matches: Optional[list[OneMatch]] = Field(None, description='匹配到具体正则的详细信息')
    match_count: Optional[int] = Field(None, description='匹配到的正则次数')


class OneQuery(BaseModel):
    query: str = Field(..., description='待匹配的字符串')
    db: str = Field('default', description='匹配的正则库 name')
    method: Literal['first', 'all', 'strict'] = Field('strict', description='匹配方法，first: 只返回第一个匹配，all: 返回所有匹配，strict: 严格匹配')
    is_sort: bool = Field(True, description='是否按照正则库中出现顺序返回，适用于 method=all/strict')
    detailed_level: Literal[1, 2, 3] = Field(2, description='1: 只返回 mark, 2: 返回 mark 和出现次数, 3: 返回详细 OneMatch')
    match_top_n: int = Field(0, description='匹配元素次数限制, 小于等于 0 代表不限制，适用于 method=all')


class RespGeneral(BaseModel):
    message: str = Field('success', description='返回信息')
    status: Optional[int] = Field(0, description='状态码')


class BodyMatch(BaseModel):
    qs: Union[list[OneQuery], OneQuery] = Field(..., description='待匹配的字符串信息列表')


class RespMatch(RespGeneral):
    result: list[list[OneMatchMark]] = Field([], description='匹配结果')
    milliseconds: float = Field(-1, description='处理时间，单位毫秒')


class RespInfo(RespGeneral):
    result: Optional[MultiRegexMatcherInfo] = Field(None, description='正则库信息')


class BodyTargets(BaseModel):
    marks: list[str] = Field(..., description='待查询的正则组mark')
    db: str = Field('default', description='正则库 name')


class RespTargets(RespGeneral):
    result: Optional[list[Optional[OneTarget]]] = Field(None, description='正则组信息列表')


class BodyFindExpression(BaseModel):
    s: str = Field(..., description='待匹配的字符串')
    exact_match: bool = Field(False, description='是否精确匹配')
    top_n: Optional[int] = Field(10, description='返回前几个, 小于等于 0 代表不限制')
    allow_flag: int = Field(-1, description='允许的 flag')
    prohibited_flag: int = Field(0, description='禁止的 flag')
    db: str = Field('default', description='正则库 name')


class RespFindExpression(RespGeneral):
    result: Optional[list[OneFindRegex]] = Field(None, description='匹配到的正则组信息列表')
