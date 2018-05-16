from setuptools import setup

setup(name='cbencryption',
      version='0.1',
      description='JSON encryption API for use with Couchbase Python SDK',
      url='http://github.com/couchbaselabs/python-json-encryption',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License', # fix license
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Database',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      keywords='funniest joke comedy flying circus',
      author='Couchbase, Inc.',
      author_email='PythonPackage@couchbase.com',
      license='MIT', # need to update this
      packages=[
          'cbencryption'
      ],
      install_requires=[
          'couchbase',
          'cryptography',
          'pyjks'
      ],
      test_suite='nose.collector',
      tests_require=[
          'nose',
          'testresources>=0.2.7',
          'basictracer==2.2.0'
      ],
      zip_safe=False)
