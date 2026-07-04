from setuptools import find_packages, setup
from symtuner import __version__

with open('./README.md') as f:
    LONG_DESCRIPTION = f.read()

setup(
    name='symtuner',
    version=__version__,
    description='SymTuner (+ naive / compose variants)',
    long_description=LONG_DESCRIPTION,
    python_version='>=3.6',
    packages=find_packages(include=('symtuner', 'symtuner.*')),
    include_package_data=True,
    install_requires=['numpy'],
    entry_points={
        'console_scripts': [
            'symtuner=symtuner.bin:main',
            'symtuner-naive=symtuner.bin_naive:main',
            'symtuner-compose=symtuner.bin_compose:main',
        ]
    }
)
