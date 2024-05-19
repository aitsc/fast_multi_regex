import hyperscan
import time
from typing import Union, Optional
from functools import lru_cache
from pydantic import BaseModel, Field
from datetime import datetime
from itertools import islice
from copy import deepcopy
from pyeda.inter import exprvar, expr
from pyeda.boolalg.expr import NaryOp as BoolOp, Variable as BoolVar
from pyeda.parsing.boolexpr import GRAMMAR
from collections import Counter
from tsc_base import replace
import re


class OneRegex(BaseModel):
    expression: str = Field(..., description="正则表达式, 或编号的布尔组合（搭配HS_FLAG_COMBINATION）")
    flag: int = Field(hyperscan.HS_FLAG_SINGLEMATCH, ge=0, description='''hyperscan 匹配标志，代码运算时可以使用 | 连接多个标志进行组合, 一些例子：
HS_FLAG_CASELESS 1: 不区分大小写；
HS_FLAG_DOTALL 2: . 匹配所有字符，包括换行符；
HS_FLAG_MULTILINE 4: 使用多行模式, 每行的开头和结尾都可以去匹配^和$；
HS_FLAG_SINGLEMATCH 8: 只匹配第一个匹配项，如果只用于 match_first 不设置这个会更快；
HS_FLAG_ALLOWEMPTY 16: 允许query是空的匹配；
HS_FLAG_SOM_LEFTMOST 256: 匹配返回开始位置，性能更慢, 和 HS_FLAG_SINGLEMATCH 不能同时使用；
HS_FLAG_COMBINATION 512: 用于组合多个正则表达式，此时 expression 可以使用 & | ! ( ) 组合多个正则表达式编号，编号为正则在 regexs 中的索引号，或者 mark.索引号。例如 "(0|1)&2" 或 "test.0|test.1&test.2"，编号必须出现在此正则编译之前, expression 不能只是单个编号；
HS_FLAG_QUIET 1024: 不输出匹配结果, 应当配合 HS_FLAG_COMBINATION 使用（例如隐藏子正则），否则请注意会影响上层包裹的其他逻辑判断''')
    # 以下参数不会作为计算 OneRegex 重复的一部分
    min_match_count: int = Field(1, ge=1, description='最少匹配次数, 必须大于等于1，大于1不能含 HS_FLAG_SINGLEMATCH 标志。约束应用在 match_strict 中，因此没有这种场景这种正则不建议出现在很多 OneTarget 里面，防止匹配次数过多对 match_all 性能产生影响')
    max_match_count: int = Field(0, ge=0, description='最多匹配次数, 必须大于等于0，0 代表不限制, 不为0不能含 HS_FLAG_SINGLEMATCH 标志')


class OneTarget(BaseModel):
    mark: str = Field(..., description='唯一标记。和 OneRegex.expression 的 HS_FLAG_COMBINATION 配合时作为str不能包含“ &|!()”')
    regexs: list[OneRegex] =Field(..., description='多个正则之间是或匹配关系')
    min_regex_count: int = Field(1, ge=0, description='regexs 最少需要满足的正则数量，必须大于等于0，考虑这个速度慢，要用 match_strict 调用才能生效，否则就是1。0 代表全部要满足')
    max_regex_count: int = Field(0, ge=0, description='regexs 最多允许满足的正则数量, 必须大于等于0。0 代表不限制')
    bool_expr: str = Field('', description='逻辑表达式，用于 match_strict 的时候，为空则不使用，使用的话 regex_count 限制不再使用，语法见 pyeda.parsing.boolexpr.GRAMMAR, 变量名为字母 r 加上正则在 regexs 中的索引号，例如 r0, r1, r2，所有正则索引都要覆盖到')
    priority: float = Field(1, description='优先级, 越小越优先返回 (在 match_all 中 sorted 为 True 的时候, 不影响正则编译顺序), 默认是 OneTarget 列表的顺序')


class MultiRegexMatcherInfo(BaseModel):
    cache_size: int = Field(0, description='缓存大小')
    last_compile_seconds: float = Field(-1, description='最后一次编译消耗秒数')
    last_compile_date: str = Field("", description='最后一次编译时间')
    # 编译统计
    compile_count: int = Field(0, description='编译次数')
    target_count: int = Field(0, description='目标数量')
    regex_count: int = Field(0, description='正则数量')
    unique_regex_count: int = Field(0, description='唯一正则数量')
    unique_target_count: int = Field(0, description='唯一目标数量, 利用 regexs/min_regex_count/max_regex_count/bool_expr 计算重复，结果和 target_count 不同可能要注意一下')
    regex_max_target_count: int = Field(0, description='单个正则匹配到的最大 target 数量')
    regex_max_mark_no_count: int = Field(0, description='单个正则匹配到的最大 (mark, regex_no) 数量. 通常和 regex_max_target_count 相等，除非 OneTarget.regexs 有重复正则')
    target_max_regex_count: int = Field(0, description='单个 target 包含的最大正则数量')
    # target 统计
    has_bool_expr_count: int = Field(0, description='有 bool_expr 的 target 数量')
    has_regex_num_limit_count: int = Field(0, description='有 min_regex_count/max_regex_count 限制的 target 数量')
    has_match_num_limit_count: int = Field(0, description='有 min_match_count/max_match_count 限制的 regex 数量')
    init_bool_true_count: int = Field(0, description='bool_expr 变量都是 False 的时候为 True 的 target 数量')
    # other
    hyperscan_size: int = Field(0, description='hyperscan 数据库大小, 单位字节')
    hyperscan_info: str = Field("", description='hyperscan 数据库信息')
    

class OneFindRegex(BaseModel):
    regex_id: int = Field(..., description='正则在数据库中的 ID')
    regex: OneRegex = Field(..., description='第一个正则, expression/flag 唯一，其他属性供参考')
    mark_count: int = Field(None, description='包含的 mark 数量')
    first_mark: str = Field(None, description='包含的第一个 mark，compile 的 targes 顺序')
    first_mark_no: int = Field(None, description='first_mark 中在 regexs 中的索引号')


class MultiRegexMatcher:
    def __init__(self, cache_size: int = 128) -> None:
        """多正则匹配器

        Args:
            cache_size (int, optional): 缓存大小, 小于等于0不使用缓存
        """
        self._db = hyperscan.Database(mode=hyperscan.HS_MODE_BLOCK)  # hyperscan 数据库
        self._mark_target: dict[str, OneTarget] = {}  # 用 mark 作为 key, 保持编译顺序
        self._mark_target_lazy: dict[str, OneTarget] = {}  # 用于延迟编译
        self._mark_target_no: dict[str, int] = {}  # 用于排序
        self._mark_bool_info: dict[str, dict] = {}  # dict 包括见 _bool_expr_process 返回的 bool_info, 用于 match_strict 的布尔判断
        self._mark_init_bool_true: dict[str, None] = {}  # 有 bool_expr 的 target, 且变量都是 False 的时候为 True
        self._mark_has_match_count_limit: dict[str, bool] = {}  # 有 min_match_count/max_match_count 限制的 target, 用于加速 match_strict
        self._id_mark_no: dict[int, dict[tuple[str, int], 1]] = {}  # 将正则匹配到的 id 映射回 mark 和 regex_no
        self._id_mark: dict[int, dict[str, 1]] = {}  # match_all 只需要对应 mark 的时候用
        self._expression_find_regexs: dict[str, list[OneFindRegex]] = {}  # 用于搜索 expression
        self._info = MultiRegexMatcherInfo(cache_size=cache_size)
        
        self._serializable_var = [  # 应当包括所有 self 需要且可序列化的变量
            '_mark_target',
            '_mark_target_lazy',
            '_mark_target_no',
            '_mark_init_bool_true',
            '_mark_has_match_count_limit',
            '_id_mark_no',
            '_id_mark',
            '_expression_find_regexs',
            '_info',
            '_serializable_var',
        ]

    def __getstate__(self):
        mark_bool_info = {}
        for mark, bool_info in self._mark_bool_info.items():
            _bool_info = mark_bool_info[mark] = {}
            if bool_info:
                _bool_info['expr'] = str(bool_info['expr'])
                _bool_info['vars'] = [str(v) for v in bool_info['vars']]
                _bool_info['vars_list'] = [str(v) for v in bool_info['vars_list']]
                
        return {
            '_db': hyperscan.dumpb(self._db),
            '_mark_bool_info': mark_bool_info,
            'serializable_var': {k: getattr(self, k) for k in self._serializable_var},
        }

    def __setstate__(self, state):
        mark_bool_info = {}
        for mark, bool_info in state['_mark_bool_info'].items():
            _bool_info = mark_bool_info[mark] = {}
            if bool_info:
                _bool_info['expr'] = expr(bool_info['expr'])
                _bool_info['vars'] = {exprvar(v): 0 for v in bool_info['vars']}
                _bool_info['vars_list'] = [exprvar(v) for v in bool_info['vars_list']]
                
        self._db = hyperscan.loadb(state['_db'], hyperscan.HS_MODE_BLOCK)
        self._db.scratch = hyperscan.Scratch(self._db)
        self._mark_bool_info = mark_bool_info
        for k, v in state['serializable_var'].items():
            setattr(self, k, v)
        self.reset_cache()
    
    def reset_cache(self, cache_size: int = None) -> bool:
        """重置缓存

        Args:
            cache_size (int, optional): 修改后的缓存大小. 为 None、小于等于0不使用缓存

        Returns:
            bool: 是否修改成功
        """
        reset_success = False
        if cache_size is not None and cache_size >= 0:
            self._info.cache_size = cache_size
        if hasattr(self.match_first, '__wrapped__'):
            self.match_first = self.match_first.__wrapped__
            self.match_all = self.match_all.__wrapped__
            self.match_strict = self.match_strict.__wrapped__
            reset_success = True
        if self._info.cache_size > 0:
            self.match_first = lru_cache(maxsize=self._info.cache_size)(self.match_first)
            self.match_all = lru_cache(maxsize=self._info.cache_size)(self.match_all)
            self.match_strict = lru_cache(maxsize=self._info.cache_size)(self.match_strict)
            reset_success = True
        return reset_success
    
    @staticmethod
    def _bool_expr_process(target: OneTarget) -> tuple[dict, bool]:
        """处理 bool_expr

        Args:
            target (OneTarget): 一个要处理的匹配对象

        Returns:
            tuple[dict, bool]: 返回 bool_info 和 init_bool_true
                bool_info:
                    expr: pyeda.inter.expr.BoolOp, 逻辑表达式
                    vars: dict[BoolVar, 0], 值默认为0的所有变量字典，有序
                    vars_list: list[BoolVar], 所有变量列表，有序
                init_bool_true: 判定 bool_expr 变量都是 False 的时候是否整个表达式为 True
        """
        bool_info = {}
        init_bool_true = False
        if target.bool_expr:
            be: BoolOp = expr(target.bool_expr)
            bool_info['expr'] = be
            vs = bool_info['vars'] = {v: 0 for v in sorted(be.support)}
            _vs = {exprvar(f"r{i}") for i in range(len(target.regexs))}
            assert _vs == set(vs), f"{target.mark}: bool_expr variables {vs} must be r0, r1, r2, ... and cover all regexs."
            bool_info['vars_list'] = list(vs)  # 用于根据 mark_regex_no 获取变量
            if be.restrict(vs):
                init_bool_true = True
        return bool_info, init_bool_true
    
    @staticmethod
    def _replace_expression_id(
        s: str,
        mark: str,
        no: int,
        mark_no_id: dict[tuple[str, int], int],
    ) -> str:
        """替换正则表达式中的编号

        Args:
            s (str): 待替换的字符串
            mark (str): 当前 expression 对于的 target 的 mark
            no (int): 当前 expression 对于的 regexs 的索引号
            mark_no_id (dict[tuple[str, int], int]): 已有 mark 和 no 到 id 的映射

        Returns:
            str: 替换后的字符串
        """
        if '.' in s:
            _mark, _no = s.rsplit('.', 1)
            _mark = type(mark)(_mark)  # mark不合适的话可能会报错
            _no = int(_no)
        else:
            _mark = mark
            _no = int(s)
        assert (_mark, _no) in mark_no_id, f"{mark}.{no}:{_mark}.{_no}: 改编号正则必须在目标正则编译之前编译/mark不合适/no不正确"
        _id = mark_no_id[(_mark, _no)]
        return str(_id)
    
    def compile(
        self,
        targets: list[Union[OneTarget, dict]] = None,
    ) -> bool:
        """编译正则表达式，编译失败不会影响已有的编译结果，该实例可正常使用

        Args:
            targets (list[Union[OneTarget, dict]]): 一组正则表达式，会深拷贝，后出现的相同mark会覆盖前面的
                有 self._mark_target_lazy 会放在 targets 前面, 使用后会清空

        Returns:
            bool: 是否重新编译
        """
        start = time.time()  # 记录编译开始时间
        if self._mark_target_lazy:
            targets = list(self._mark_target_lazy.values()) + (targets or [])
        if not targets:
            return False
        # 转换为 OneTarget 对象
        targets = [OneTarget(**target) if isinstance(target, dict) else target for target in targets]
        mark_target = {t.mark: t for t in targets}  # 用 mark 作为 key, 保持编译顺序
        if list(mark_target.items()) == list(self._mark_target.items()):  # 如果和上次一样就不重新编译
            return False
        mark_target = deepcopy(mark_target)  # 防止 target 后续修改
        expression_id_pattern = re.compile(r'[^&|!() ]+')  # 匹配 expression 的id变量
        # 变量解析
        id_mark_no = {}
        id_mark = {}
        mark_bool_info = {}
        mark_init_bool_true = {}
        expression_find_regexs = {}
        # 临时变量
        mark_no_id: dict[tuple[str, int], int] = {}
        expr_flag_id: dict[tuple[str, int], int] = {}
        expressions: list[bytes] = []
        flags: list[int] = []
        ids: list[int] = []
        for t in mark_target.values():
            assert t.regexs, f"{t.mark}.regexs: Can not be empty"
            assert t.min_regex_count >= 0, f"{t.mark}.min_regex_count: Not satisfied with {t.min_regex_count} >= 0"
            assert t.max_regex_count >= t.min_regex_count and t.min_regex_count != 0 or t.max_regex_count == 0, f"{t.mark}.max_regex_count: Not satisfied with {t.max_regex_count} >= {t.min_regex_count} and {t.min_regex_count} != 0 or {t.max_regex_count} == 0"
            bool_info, init_bool_true = self._bool_expr_process(t)
            mark_bool_info[t.mark] = bool_info
            if init_bool_true:
                mark_init_bool_true[t.mark] = None
            for no, r in enumerate(t.regexs):
                assert r.min_match_count >= 1, f"{t.mark}-{no}.min_match_count: Not satisfied with {r.min_match_count} >= 1"
                assert r.max_match_count >= r.min_match_count or r.max_match_count == 0, f"{t.mark}-{no}.max_match_count: Not satisfied with {r.max_match_count} >= {r.min_match_count} or {r.max_match_count} == 0"
                if r.min_match_count > 1 or r.max_match_count > 0:
                    # r.flag &= ~hyperscan.HS_FLAG_SINGLEMATCH  # 主动修改会影响重复编译判定
                    assert r.flag & hyperscan.HS_FLAG_SINGLEMATCH == 0, f"{t.mark}-{no}.flag: Can not contain HS_FLAG_SINGLEMATCH"
                    self._mark_has_match_count_limit[t.mark] = True
                if (r.expression, r.flag) in expr_flag_id:
                    _id = expr_flag_id[(r.expression, r.flag)]
                else:
                    _id = expr_flag_id[(r.expression, r.flag)] = len(expr_flag_id)
                    ids.append(_id)
                    flags.append(r.flag)
                    # 替换 expression 中的编号
                    if r.flag & hyperscan.HS_FLAG_COMBINATION:
                        expression = replace(
                            expression_id_pattern, 
                            lambda s: self._replace_expression_id(s, t.mark, no, mark_no_id),
                            r.expression)
                        expressions.append(expression.encode('utf-8'))
                    else:
                        expressions.append(r.expression.encode('utf-8'))
                    # 记录信息
                    if r.expression not in expression_find_regexs:
                        expression_find_regexs[r.expression] = [OneFindRegex(regex_id=_id, regex=r)]
                    else:
                        expression_find_regexs[r.expression].append(OneFindRegex(regex_id=_id, regex=r))
                # 记录信息
                id_mark_no.setdefault(_id, {})[(t.mark, no)] = 1
                mark_no_id[(t.mark, no)] = _id
                id_mark.setdefault(_id, {})[t.mark] = 1
        for find_regexs in expression_find_regexs.values():
            find_regexs: list[OneFindRegex]
            for find_regex in find_regexs:
                find_regex.mark_count = len(id_mark[find_regex.regex_id])
                find_regex.first_mark, find_regex.first_mark_no = next(iter(id_mark_no[find_regex.regex_id]))
        # 编译
        self._db.compile(expressions=expressions, ids=ids, flags=flags)
        self._mark_target_no = {t.mark: no for no, t in enumerate(sorted(mark_target.values(), key=lambda t: t.priority))}
        self._mark_bool_info = mark_bool_info
        self._mark_init_bool_true = mark_init_bool_true
        self._mark_target = mark_target
        self._id_mark_no = id_mark_no
        self._id_mark = id_mark
        self._expression_find_regexs = expression_find_regexs
        self._mark_target_lazy.clear()
        self.reset_cache()
        # 统计信息
        self._info.hyperscan_size = self._db.size()
        self._info.hyperscan_info = self._db.info()
        if isinstance(self._info.hyperscan_info, bytes):
            self._info.hyperscan_info = self._info.hyperscan_info.decode('utf-8')
        self._info.unique_target_count = len(set(f'{t.regexs}/{t.min_regex_count}/{t.max_regex_count}/{t.bool_expr}' for t in mark_target.values()))
        self._info.regex_max_target_count = max(len(mm) for mm in self._id_mark.values())
        self._info.regex_max_mark_no_count = max(len(mm) for mm in self._id_mark_no.values())
        self._info.target_max_regex_count = max(len(t.regexs) for t in self._mark_target.values())
        self._info.has_regex_num_limit_count = sum(t.min_regex_count != 1 or t.max_regex_count != 0 for t in self._mark_target.values())
        self._info.has_match_num_limit_count = sum(r.min_match_count != 1 or r.max_match_count != 0 for t in self._mark_target.values() for r in t.regexs)
        self._info.has_bool_expr_count = sum(bool(bool_info) for bool_info in self._mark_bool_info.values())
        self._info.init_bool_true_count = len(self._mark_init_bool_true)
        self._info.compile_count += 1
        self._info.target_count = len(self._mark_target)
        self._info.regex_count = sum(len(t.regexs) for t in self._mark_target.values())
        self._info.unique_regex_count = len(self._id_mark)
        self._info.last_compile_seconds = time.time() - start
        self._info.last_compile_date = datetime.now().isoformat()
        return True
    
    def insert_targets(
        self, 
        targets: list[Union[OneTarget, dict]], 
        index: int = -1,
        lazy_compilation: bool = False,
    ) -> bool:
        """插入目标

        Args:
            targets (list[Union[OneTarget, dict]]): 一组正则表达式
            index (int, optional): 插入位置, -1 代表末尾
            lazy_compilation (bool, optional): 是否延迟编译, 等下次 compile 一起编译

        Returns:
            bool: 是否重新编译
        """
        mark_target = self._mark_target_lazy if lazy_compilation and self._mark_target_lazy else self._mark_target
        _targets = list(mark_target.values())
        if index == -1:
            _targets += targets
        else:
            _targets[index:index] = targets
        if lazy_compilation:
            self._mark_target_lazy = {t.mark: t for t in _targets}
            return False
        return self.compile(_targets)

    def delete_targets(
        self, 
        marks: list[str],
        lazy_compilation: bool = False,
    ) -> bool:
        """删除目标

        Args:
            marks (list[str]): 一组 mark
            lazy_compilation (bool, optional): 是否延迟编译, 等下次 compile 一起编译

        Returns:
            bool: 是否重新编译
        """
        marks = set(marks)
        mark_target = self._mark_target_lazy if lazy_compilation and self._mark_target_lazy else self._mark_target
        if lazy_compilation:
            self._mark_target_lazy = {m: t for m, t in mark_target.items() if m not in marks}
            return False
        _targets = [t for t in mark_target.values() if t.mark not in marks]
        return self.compile(_targets)
    
    def update_targets(
        self, 
        targets: list[Union[OneTarget, dict]], 
        allow_new: bool = True,
        lazy_compilation: bool = False,
    ) -> bool:
        """更新目标内容

        Args:
            targets (list[Union[OneTarget, dict]]): 一组正则表达式，使用dict可以只更新部分属性
            allow_new (bool, optional): 是否允许新增目标, 新增会直接添加到末尾
            lazy_compilation (bool, optional): 是否延迟编译, 等下次 compile 一起编译

        Returns:
            bool: 是否重新编译
        """
        mark_target = self._mark_target_lazy if lazy_compilation and self._mark_target_lazy else self._mark_target
        mark_target = mark_target.copy()
        for t in targets:
            if isinstance(t, dict):
                _t = dict(mark_target.get(t['mark'], {
                    'mark': t['mark'],
                }))
                _t.update(t)  # 保留原有的未新增属性
                t = OneTarget(**_t)
            if allow_new or t.mark in mark_target:
                mark_target[t.mark] = t
        if lazy_compilation:
            self._mark_target_lazy = mark_target
            return False
        _targets = list(mark_target.values())
        return self.compile(_targets)
    
    def exchange_targets(
        self,
        mark_to_mark: list[tuple[str, str]],
        mark_is_no: bool = False,
        lazy_compilation: bool = False,
    ) -> bool:
        """交换目标位置

        Args:
            mark_to_mark (list[tuple[str, str]]): 一组 mark 交换位置
            mark_is_no (bool, optional): mark 是否是排序号
            lazy_compilation (bool, optional): 是否延迟编译, 等下次 compile 一起编译

        Returns:
            bool: 是否重新编译
        """
        mark_target = self._mark_target_lazy if lazy_compilation and self._mark_target_lazy else self._mark_target
        _targets = list(mark_target.values())
        if mark_is_no:
            for no1, no2 in mark_to_mark:
                _targets[no1], _targets[no2] = _targets[no2], _targets[no1]
        else:
            mark_no = {m: no for no, m in enumerate(mark_target)}
            for m1, m2 in mark_to_mark:
                no1, no2 = mark_no[m1], mark_no[m2]
                _targets[no1], _targets[no2] = _targets[no2], _targets[no1]
        if lazy_compilation:
            self._mark_target_lazy = {t.mark: t for t in _targets}
            return False
        return self.compile(_targets)
    
    def match_event_callback(self, id: int, start: int, end: int, flags: int, context: dict):
        """匹配事件处理器

        Args:
            id (int): hyperscan 数据库中的正则 ID
            start (int): 匹配到的开始位置，从0开始，没有设置HS_FLAG_SOM_LEFTMOST的话为0
            end (int): 匹配到的结束位置，从0开始
            flags (int): 匹配标志
            context (dict): 上下文信息

        Raises:
            StopIteration: 用于只匹配第一个的时候
            ValueError: 用于 detailed_level 不在 1, 2, 3 的时候
            StopIteration: 用于匹配次数限制
        """
        if context.get('only_first'):
            mark, regex_no = next(iter(self._id_mark_no[id]))  # 占将近 10% 的时间
            context['match'] = mark, {  # OneMatch 格式, dict 返回占 20% 的时间
                # 'regex_id': id,  # 正则在数据库中的 ID
                'start': start,  # 匹配开始位置，从0开始
                'end': end,  # 匹配结束位置，从0开始
                # 'flags': flags,  # 匹配标志
                # 'mark': mark,  # OneTarget 的标记
                'match_no': 0,  # 总共第几次匹配到的，从0开始
                'mark_regex_no': regex_no,  # OneTarget.regexs 中的第几个正则匹配到的，从0开始
                # 'mark_no': self._mark_target_no[mark],  # OneTarget 的排序号，从0开始
            }
            raise StopIteration
        else:
            if context['detailed_level'] == 1:  # 只记录匹配的 mark
                if context['match_top_n'] <= 0:
                    context['matches'].update(self._id_mark[id])
                else:
                    context['matches'].update(islice(self._id_mark[id].items(), context['match_top_n'] - context['match_count']))
                    context['match_count'] = len(context['matches'])
            elif context['detailed_level'] == 2:  # 记录匹配的 mark 和出现 count
                if context['match_top_n'] <= 0:
                    for k in self._id_mark[id]:
                        context['matches'].setdefault(k, 0)
                        context['matches'][k] += 1
                else:
                    for k in islice(self._id_mark[id], context['match_top_n'] - context['match_count']):
                        context['matches'].setdefault(k, 0)
                        context['matches'][k] += 1
                    context['match_count'] = len(context['matches'])
            elif context['detailed_level'] == 3:  # 记录详细匹配信息
                if context['match_top_n'] <= 0:
                    for k in self._id_mark_no[id]:
                        mark, regex_no = k
                        context['matches'].setdefault(mark, []).append({
                            # 'regex_id': id,
                            'start': start,
                            'end': end,
                            # 'flags': flags,
                            # 'mark': mark,
                            'match_no': context['match_regex_no'],
                            'mark_regex_no': regex_no,
                        })
                else:
                    for k in islice(self._id_mark_no[id], context['match_top_n'] - context['match_count']):
                        mark, regex_no = k
                        context['matches'].setdefault(mark, []).append({
                            # 'regex_id': id,
                            'start': start,
                            'end': end,
                            # 'flags': flags,
                            # 'mark': mark,
                            'match_no': context['match_regex_no'],
                            'mark_regex_no': regex_no,
                        })
                        context['match_count'] += 1
                context['match_regex_no'] += 1
            else:
                raise ValueError("detailed_level must be 1, 2 or 3.")
            if 0 < context['match_top_n'] <= context['match_count']:
                raise StopIteration

    def match_first(self, s: str) -> Union[tuple[str, dict], None]:
        """匹配第一个，速度较快，不考虑 regex_count 限制和 bool_expr

        Args:
            s (str): 待匹配的字符串

        Returns:
            Union[tuple[str, dict], None]: 匹配到的信息，None 代表没有匹配到，dict 为 OneMatch 格式
        """
        assert self._info.compile_count, "Please compile first."
        context = {  # context 格式
            'match': None,  # 匹配到的信息, 用于 match_first
            'only_first': True,  # 是否只匹配第一个，用于 match_first
        }
        try:
            self._db.scan(s.encode('utf-8'), self.match_event_callback, context=context)
        except:
            ...
        return context.get('match')

    def match_all(
        self,
        s: str,
        is_sort: bool = True,
        detailed_level: int = 1,
        match_top_n: int = 0,
    ) -> Union[dict[str, Union[list[dict], int]], list[str]]:
        """匹配所有，速度较慢，不考虑 regex_count 限制和 bool_expr

        Args:
            s (str): 待匹配的字符串
            is_sort (bool, optional): 是否按照提供的优先级排序 mark, 否则为匹配到的顺序（第一个出现正则的顺序，相同出现为编译的 targets 顺序）
            detailed_level (int, optional): 详细匹配信息等级, 1: 只返回 mark, 2: 返回 mark 和出现次数, 3: 返回详细匹配信息. 越高性能有一点点影响
            match_top_n (int, optional): 匹配元素次数限制, 小于等于 0 代表不限制
                detailed_level==3 限制的是 (mark,regex_no) 数量, 否则是 mark 数量

        Returns:
            Union[dict[str, Union[list[dict], int]], list[str]]: 匹配到的信息，内层 dict 为 OneMatch 格式，list 为 mark
        """
        assert self._info.compile_count, "Please compile first."
        context = {  # context 格式
            'detailed_level': detailed_level,  # 是否返回详细匹配信息, 用于 match_all
            'match_top_n': match_top_n,  # 匹配元素次数限制, 0 代表不限制
            'match_regex_no': 0,  # 匹配到的正则数量，从0开始
            'matches': {},  # dict[str, Union[int, list[OneMatch]]]
            'match_count': 0,  # 匹配元素次数，用于 match_top_n 限制，元素可能是 mark 或者 (mark,regex_no)
        }
        try:
            self._db.scan(s.encode('utf-8'), self.match_event_callback, context=context)
        except:
            ...
        # 排序
        if is_sort:
            matches = {k: v for k, v in sorted(context['matches'].items(), key=lambda x: self._mark_target_no[x[0]])}
        else:
            matches = context['matches']
        if detailed_level == 1:
            matches = list(matches)
        return matches

    def match_strict(
        self,
        s: str,
        is_sort: bool = True,
    ) -> dict[str, list[dict]]:
        """匹配严格的，速度较慢，要求满足 bool_expr 或没有 bool_expr 满足 regex_count 限制
        要遍历 mark_init_bool_true 以及 match_all 的结果，包括布尔运算，所以速度较慢，加速建议：
            - 不要留太多初始未匹配到正则就为 True 的 bool_expr  (init_bool_true_count)
            - 尽量减少相同 OneRegex 同时包含在很多 OneTarget 中的情况  (regex_max_target_count)
            - 尽量减少 bool_expr 的使用  (has_bool_expr_count)
            - 减少这种情况: 可预见的 s 会匹配到大量的 OneTarget 和 OneRegex
            - 设置 HS_FLAG_SINGLEMATCH
        这个方法用 first 没有意义，一个是每次匹配到都做判定有性能问题，另一个是首次匹配到也不代表后面还能匹配到（例如最后来个not）

        Args:
            s (str): 待匹配的字符串
            is_sort (bool, optional): 是否按照提供的优先级排序 mark, 否则为匹配到的顺序（第一个出现正则的顺序，相同出现为编译的 targets 顺序）
                已排序结果也可以用下面的方法还原顺序：
                for k, v in sorted(matches.items(), key=lambda x: x[1][0]['match_no'] if x[1] else float('inf'))

        Returns:
            dict[str, list[dict]]: 匹配到的信息，内层 dict 为 OneMatch 格式，list 可能为空（当存在无匹配时mark布尔表达式为true的时候）
        """
        matches = self.match_all(s, is_sort=False, detailed_level=3, match_top_n=0)
        mark_init_bool_true = [(mark, []) for mark in self._mark_init_bool_true if mark not in matches]
        for mark, mm in list(matches.items()):
            target = self._mark_target[mark]
            if self._mark_has_match_count_limit.get(mark):
                # 都用这个大概占据 match_strict 20% 的时间
                regex_no_s = [no for no, c in Counter(m['mark_regex_no'] for m in mm).items(
                    ) if (target.regexs[no].max_match_count or c) >= c >= target.regexs[no].min_match_count]
            else:
                regex_no_s = set(m['mark_regex_no'] for m in mm)
            bool_info = self._mark_bool_info.get(mark)
            if bool_info:  # 占用 25% 的时间
                vs: dict = bool_info['vars'].copy()
                vs_l: list = bool_info['vars_list']
                vs.update((vs_l[no], 1) for no in regex_no_s)
                if not bool_info['expr'].restrict(vs):
                    del matches[mark]
            elif not ((target.min_regex_count or len(target.regexs)) <= len(regex_no_s) <= (target.max_regex_count or len(regex_no_s))):
                del matches[mark]  # mm, list[OneMatch]
        matches.update(mark_init_bool_true)
        if is_sort:
            matches = {k: v for k, v in sorted(matches.items(), key=lambda x: self._mark_target_no[x[0]])}
        return matches
    
    @property
    def info(self) -> MultiRegexMatcherInfo:
        """获取统计信息, 不能修改返回值

        Returns:
            MultiRegexMatcherInfo: 统计信息
        """
        return self._info
    
    def get_target(self, mark: str) -> Union[OneTarget, None]:
        """获取目标，不能修改返回值

        Args:
            mark (str): 目标标记

        Returns:
            Union[OneTarget, None]: 目标
        """
        return self._mark_target.get(mark)
    
    def find_expression(
        self, 
        s: str, 
        exact_match: bool = False,
        top_n: Optional[int] = None,
        allow_flag: int = -1,
        prohibited_flag: int = 0,
    ) -> list[OneFindRegex]:
        """查找正则表达式

        Args:
            s (str): 待查找的字符串
            exact_match (bool, optional): 是否精确匹配（速度快）, 否则使用正则搜索(速度慢)
            top_n (Optional[int], optional): 最多返回的数量, None 代表不限制
            allow_flags (int, optional): 允许的 flag, 按位&, -1 代表不限制, 优先级高于 prohibited_flag
            prohibited_flag (int, optional): 禁止的 flag, 按位&, 0 代表不限制

        Returns:
            list[OneFindRegex]: 匹配到的正则表达式信息，按 compile 的 targes 顺序, 不可修改返回结果
        """
        if exact_match:
            find_regexs = self._expression_find_regexs.get(s, [])
            if allow_flag != -1:
                find_regexs = [r for r in find_regexs if r.regex.flag & allow_flag]
            if prohibited_flag != 0:
                find_regexs = [r for r in find_regexs if not r.regex.flag & prohibited_flag]
            return find_regexs[:top_n]
        
        pattern = re.compile(s)
        find_regexs = []
        for e, rs in self._expression_find_regexs.items():
            if pattern.search(e):
                if allow_flag != -1:
                    rs = [r for r in rs if r.regex.flag & allow_flag]
                if prohibited_flag != 0:
                    rs = [r for r in rs if not r.regex.flag & prohibited_flag]
                find_regexs.extend(rs)
                if top_n is not None and len(find_regexs) >= top_n:
                    break
        return find_regexs[:top_n]
