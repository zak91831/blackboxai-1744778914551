"""
Setup configuration for CacheXSSDetector package.
"""

from setuptools import setup, find_packages
import os

# Read the contents of README.md
with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

# Read the requirements
with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Read the development requirements
with open("requirements-dev.txt", encoding="utf-8") as f:
    dev_requirements = [
        line.strip() 
        for line in f 
        if line.strip() and not line.startswith("#") and not line.startswith("-r")
    ]

setup(
    name="cachexssdetector",
    version="1.0.0",
    description="A sophisticated security tool for detecting cache-based XSS vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Research Team",
    author_email="security@example.com",
    url="https://github.com/yourusername/CacheXSSDetector",
    packages=find_packages(exclude=["tests*", "docs*"]),
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "cachexssdetector=CacheXSSDetector.cachexssdetector:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    include_package_data=True,
    package_data={
        "CacheXSSDetector": [
            "config/*.json",
            "reporting_module/templates/*.html",
        ],
    },
    zip_safe=False,
    platforms="any",
)
