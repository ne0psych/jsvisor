from setuptools import setup, find_packages

setup(
    name="jsvisor",
    version="4.0.0",
    description="JSVisor -- Advanced JavaScript Security Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="JSVisor Contributors",
    license="MIT",
    packages=find_packages(),
    py_modules=["js_analyzer"],
    python_requires=">=3.9",
    install_requires=[
        "textual>=0.40.0",
        "esprima>=4.0.1",
        "pathspec>=0.11.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "crypto": ["pycryptodome>=3.19.0"],
    },
    entry_points={
        "console_scripts": [
            "jsvisor=js_analyzer:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="javascript security scanner static-analysis secrets endpoints",
)
