from setuptools import setup, find_packages

setup(
    name="mobileaudit",
    version="0.1.0",
    description="Enterprise mobile device security assessment tool (iOS & Android)",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "click>=8.1.7",
    ],
    extras_require={
        "ios": ["pymobiledevice3>=4.0.0"],
        "dev": ["pytest>=7.4.0", "pytest-cov>=4.1.0"],
    },
    entry_points={
        "console_scripts": [
            "mobileaudit=mobileaudit.cli:main",
        ],
    },
)
