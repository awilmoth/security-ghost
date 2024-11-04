from setuptools import setup, find_packages

setup(
    name="security-ghost",
    version="0.1.0",
    author="Your Name",
    description="A security tool for network anonymization",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "requests",
        "python-decouple",
        "PySocks",
        "python-wireguard",
    ],
    entry_points={
        'console_scripts': [
            'security-ghost=security_ghost.skeleton:run',
        ],
    },
)