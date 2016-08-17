from setuptools import setup, find_packages

setup(
    name='netflow-collector',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'psycopg2',
    ],
    entry_points='''
        [console_scripts]
        nfc-daemon=netflow_collector.daemon:multi
    ''',
)
