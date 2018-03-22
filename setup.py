from setuptools import setup, find_packages

setup(name="chopshop",
      version="4.5",
      description="ChopShop",
      author="MITRE",
      author_email="",
      python_requires='>=2.6,<3.0',
      install_requires=[
          'future',
          'pynids',
          'htpy',
          'argparse;python_version<"2.7"',
      ],
      packages=find_packages(exclude=["*.tests",
                                      "*.tests.*",
                                      "tests.*",
                                      "tests"]),
      entry_points={
        'console_scripts': ['chopshop=chopshop.shop.ChopShop:main',
                            'chopshop-newmod=chopshop.shop.ChopNewMod:main',
                            'suture=chopshop.shop.ChopSuture:main']}
      )
