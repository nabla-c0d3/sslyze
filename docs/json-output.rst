Exporting and processing scan results in JSON
#############################################

The result of SSLyze scans can be serialized to JSON for further processing. SSLyze also provides a helper class to
parse JSON scan results; it can be used to process the results of SSLyze scans in a separate Python program.

A schema of the JSON output is available in the code repository at
`./json_output_schema.json <https://github.com/nabla-c0d3/sslyze/blob/release/json_output_schema.json>`_.

JSON output when using the CLI
******************************

When using the CLI, the scan results can be exported to a JSON file using the ``--json_out`` option::

    $ python -m sslyze www.google.com www.facebook.com --json_out=result.json

The generated JSON file can then be parsed using the ``SslyzeOutputAsJson.from_file()`` method:

.. literalinclude:: ../api_sample.py
    :pyobject: example_json_result_parsing

The resulting Python object then contains the scan results. Type annotations are available for all fields, thereby
making it easier to process the results.

.. autoclass:: SslyzeOutputAsJson
