import os
from setuptools import setup

long_description = 'See https://github.com/couchbase/python-couchbase-encryption for more details'
if os.path.exists('README.md'):
    long_description = open('README.md').read()

setup(name='cbencryption',
      version='0.2.0',
      description='JSON encryption API for use with Couchbase Python SDK',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/couchbase/python-couchbase-encryption',
      classifiers=[
        'Development Status :: 4 - Beta',
        'License :: Other/Proprietary License',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Database',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      keywords='couchbase nosql encryption json',
      author='Couchbase, Inc.',
      author_email='PythonPackage@couchbase.com',
      license='Proprietary',
      python_requires='>=3',
      packages=[
          'cbencryption'
      ],
      include_package_data=True,
      install_requires=[
          'couchbase',
          'cryptography'
      ],
      test_suite='nose.collector',
      tests_require=[
          'nose',
          'testresources>=0.2.7',
          'basictracer==2.2.0',
      ],
      zip_safe=True)
