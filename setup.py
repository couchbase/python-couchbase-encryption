import os
from setuptools import setup

long_description = 'See https://github.com/couchbase/python-couchbase-encryption for more details'
if os.path.exists('README.md'):
    long_description = open('README.md').read()

setup(name='cbencryption',
      version='0.1.2',
      description='JSON encryption API for use with Couchbase Python SDK',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='http://github.com/couchbaselabs/python-json-encryption',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: Other/Proprietary License',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Database',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      keywords='couchbase nosql encryption',
      author='Couchbase, Inc.',
      author_email='PythonPackage@couchbase.com',
      license='Proprietary',
      packages=[
          'cbencryption'
      ],
      include_package_data=True,
      install_requires=[
          'couchbase',
          'cryptography',
          'pyjks'
      ],
      test_suite='nose.collector',
      tests_require=[
          'nose',
          'testresources>=0.2.7',
          'basictracer==2.2.0',
          'opentracing-pyzipkin'
      ],
      zip_safe=True)
