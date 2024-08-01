# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open('fast_multi_regex/version.txt', 'r') as f:
    version = f.read().strip()
with open('readme.md', 'r') as f:
    long_description = f.read()

setup(
    name='fast_multi_regex',
    version=version,
    description="Fast multi-regex, multi-pattern, boolean expression matching",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='tanshicheng',
    license='GPLv3',
    url='https://github.com/aitsc/fast_multi_regex',
    keywords='tools',
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development :: Libraries',
    ],
    install_requires=[
        'hyperscan>=0.7.7',
        'pydantic',
        'pyeda',
        'tsc-base',
        'fastapi',
        'uvicorn',
        'watchdog',
        'asyncio',
        'requests',
        'aiohttp',
        'pyyaml',
        'toml',
        'jsoncomment',
        'prometheus-client',
    ],
    entry_points={  # 打包到bin
        'console_scripts': [
            'fast_multi_regex_server=fast_multi_regex.server:app_server',  # 包不能有-符号
        ],
    },
    python_requires='>=3.9',
)
