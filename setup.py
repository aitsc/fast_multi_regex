# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import os

if os.path.exists('readme.md'):
    long_description = open('readme.md', 'r', encoding='utf8').read()
else:
    long_description = 'https://github.com/aitsc/fast_multi_regex'

setup(
    name='fast_multi_regex',
    version='0.4',
    description="",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='tanshicheng',
    license='GPLv3',
    url='https://github.com/aitsc/fast_multi_regex',
    keywords='tools',
    packages=find_packages(),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development :: Libraries',
    ],
    install_requires=[
        'hyperscan',
        'pydantic',
        'pyeda',
        'tsc-base',
        'fastapi',
        'uvicorn',
        'watchdog',
        'asyncio',
        'requests',
    ],
    entry_points={  # 打包到bin
        'console_scripts': [
            'fast_multi_regex_server=fast_multi_regex.server:main',  # 包不能有-符号
        ],
    },
    python_requires='>=3.7',
)
