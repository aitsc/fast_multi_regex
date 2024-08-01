# 介绍

- 快速多正则多模匹配，10万个正则表达式编译2分钟，匹配1千次耗时最低0.003s以内，支持多正则之间的布尔运算匹配，基于 hyperscan / pyeda
- 提供封装的 HTTP 服务，编译和匹配过程使用不同进程，支持热更新正则库

## 使用
```shell
pip install fast-multi-regex
fast_multi_regex_server --help
fast_multi_regex_server
```

构建正则库，即增删改 matchers_config_folder 中的 json 文件（允许子文件夹嵌套，不能以 . 开头），也支持其他格式的配置文件，包括 .jsonc .toml .yaml，格式和 json 一样，可以使用注释。json 文件例子参数解释：
```json
{ // 一个正则库, 超过 10 万不重复的 regex 建议拆分成多个库
    "cache_size": 128, // match 接口查询的缓存大小
    "literal": false, // 是否使用字面量匹配（用于正则当作普通字符更快匹配，但是大部分flag失效）
    "targets": [ // 如果要删除一个线上库不能直接将 targets 置空，而是要删除配置文件，空 targets 的配置不会被解析
        {
            "mark": "example", // 正则组名称，不能重复。不提供或为空则默认为 auto_i，i 为 targets 中所在的索引，从1开始
            "regexs": [
                {
                    "expression": "例子", // 正则表达式, 或编号的布尔组合（搭配HS_FLAG_COMBINATION标志，支持 & | ~ () 运算符，编号为正则在 regexs 中的索引号，或者 mark.索引号。例如 "(0|1)&2" 或 "test.0|test.1&test.2"）
                    "flag": 40, // hyperscan flag，例如 40 代表一个正则只匹配一次，并且以字符而不是字节为单位匹配
                    "flag_ext": { // 扩展标志，null 代表不使用
                        "min_offset": null, // 最小偏移量, 匹配的结束位置大于等于这个
                        "max_offset": null, // 最大偏移量, 匹配的结束位置小于等于这个
                        "min_length": null, // 最小长度，匹配到的长度要大于等于这个
                        "edit_distance": null, // 在给定的编辑距离(用于计算从一个字符串转换到另一个字符串所需要的最少单字符编辑操作数)内匹配此表达式
                        "hamming_distance": null // 在给定的汉明距离(计算在相同位置上字符不同的数量,只适用于长度相同的字符串)内匹配此表达式
                    },
                    "min_match_count": 1, // 最少匹配次数, 必须大于等于1，大于1不能含HS_FLAG_SINGLEMATCH标志，适用于 match_strict
                    "max_match_count": 0 // 最多匹配次数，0 代表不限制，适用于 match_strict
                }
            ],
            "min_regex_count": 1, // regexs 最少需要满足的正则数量，必须大于等于0，0 代表全部要满足，适用于 match_strict
            "max_regex_count": 0, // regexs 最多允许满足的正则数量, 必须大于等于0。0 代表不限制，适用于 match_strict
            "bool_expr": "", // 逻辑表达式，为空则不使用，使用则 regex_count 限制失效，适用于 match_strict。支持 => <=> :? ^ & | ~ () 运算符, 变量名为字母 r 加上正则在 regexs 中的索引号，例如 r0, r1, r2，所有正则索引都要覆盖到
            "priority": 1, // 优先级, 越小越优先返回，需要 is_sort=true
            "meta": {} // 元数据，可以不提供 或 null 或 object，用于匹配返回时携带
        }
    ]
}
```

访问 `http://127.0.0.1:8000/docs` 查看接口文档，接口访问例子：
```shell
curl -X 'POST' \
  'http://127.0.0.1:8000/match' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer test' \
  -H 'Content-Type: application/json' \
  -d '{
  "qs": [
    {
      "query": "这是一个例子",
      "db": "default",
      "method": "strict",
      "is_sort": true,
      "detailed_level": 2,
      "match_top_n": 0
    }
  ]
}'
```

直接调包使用：
```python
from fast_multi_regex import MultiRegexMatcher
mr = MultiRegexMatcher()
targets = [
    {
        "mark": "test",
        "regexs": [
            {
                "expression": "test",
            }
        ],
    }
]
mr.compile(targets)
print(mr.match_first("test"))
```

可以配置 prometheus.yml 查看统计指标：
```yaml
scrape_configs:
  - job_name: fast_multi_regex_server
    bearer_token: test
    static_configs:
      - targets: ['127.0.0.1:8000']
```

## 不同配置文件的读取速度测试
仅供参考，速度 JSON > JSONC > TOML > YAML，不需要注释最好用 JSON，target 数量不太多的情况下 YAML 也可以接受。
```
# 1000 对象
读取 JSON 文件的平均时间: 0.001775 秒
读取 YAML 文件的平均时间: 0.373537 秒
读取 TOML 文件的平均时间: 0.080640 秒
读取 JSONC 文件的平均时间: 0.010024 秒
读取 YAML 文件相对于 JSON 慢了 210.49 倍
读取 TOML 文件相对于 JSON 慢了 45.44 倍
读取 JSONC 文件相对于 JSON 慢了 5.65 倍

# 100 对象
读取 JSON 文件的平均时间: 0.000653 秒
读取 YAML 文件的平均时间: 0.037624 秒
读取 TOML 文件的平均时间: 0.008857 秒
读取 JSONC 文件的平均时间: 0.001412 秒
读取 YAML 文件相对于 JSON 慢了 57.58 倍
读取 TOML 文件相对于 JSON 慢了 13.56 倍
读取 JSONC 文件相对于 JSON 慢了 2.16 倍
```
