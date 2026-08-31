from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="security-monitor",
    version="1.0.0",
    author="Ilyas Rifai",
    author_email="email@anda.com",
    description="Security Monitor Dashboard",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ilyas7/security-monitor",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
    install_requires=[
        "streamlit>=1.28.0",
        "pandas>=1.3.0",
        "numpy>=1.21.0",
        "plotly>=5.10.0",
        "python-dateutil>=2.8.0",
    ],
)