from setuptools import setup, find_packages

setup(
    name='nullsec-ctf',
    version='1.0.0',
    description='All-in-one CTF helper tool',
    author='bad-antics',
    author_email='bad-antics@github.com',
    url='https://github.com/bad-antics/nullsec-ctf',
    py_modules=['nullsec_ctf'],
    entry_points={
        'console_scripts': [
            'ctf=nullsec_ctf:main',
        ],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
)
