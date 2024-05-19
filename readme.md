# 介绍

快速多正则多模匹配，10万个正则表达式编译2分钟，匹配1千次耗时最低0.003s以内，支持多正则之间的布尔运算匹配，基于 hyperscan / pyeda

## 使用
```shell
pip install fast-multi-regex
fast_multi_regex_server --help
fast_multi_regex_server
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
      "query": "test",
      "db": "default",
      "method": "strict",
      "is_sort": true,
      "detailed_level": 2,
      "match_top_n": 0
    }
  ]
}'
```

构建正则库，matchers_config_folder 内 json 文件例子：
```json
{
    "cache_size": 128,
    "targets": [
        {
            "mark": "test",
            "regexs": [
                {
                    "expression": "test",
                    "flag": 8,
                    "min_match_count": 1,
                    "max_match_count": 0
                }
            ],
            "min_regex_count": 1,
            "max_regex_count": 0,
            "bool_expr": "",
            "priority": 1
        }
    ]
}
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
