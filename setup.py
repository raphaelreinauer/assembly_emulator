# setup.py

import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="assembly_emulator",  # Replace with your desired package name
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A Python package to assemble, emulate, and debug x86_64 assembly code using Unicorn and Keystone.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/raphaelreinauer/assembly_emulator",  # Replace with your repository URL
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "unicorn",
        "keystone-engine",
        "capstone",
    ],
    entry_points={
        'console_scripts': [
            'assembly_emulator=assembly_emulator.emulator:main',
        ],
    },
)
