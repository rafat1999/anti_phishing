from setuptools import setup, find_packages

setup(
    name="anti-phishing",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "colorama>=0.4.6",
        "firebase-admin>=6.2.0",
        "aiohttp>=3.8.5",
        "nest-asyncio>=1.5.7",
    ],
    entry_points={
        "console_scripts": [
            "anti-phishing=anti_phishing.cli:main",
        ],
    },
    author="Engr. Shihab Hossen Rafat",
    author_email="rafat.cit.bd@gmail.com",
    description="An anti-phishing system for educational institutions. All Rights Are Reserved By Creative Business Group | Creative IT Institute | Creative Skills | atl",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/rafat1999/anti_phishing.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: Developed By The Cyber Team of Creative IT Institute",  # Optional: Development stage
    ],
    python_requires=">=3.7",
)
