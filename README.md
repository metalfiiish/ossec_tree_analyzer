# ossec_tree_analyzer
A tool that can help to parse large ossec rule files and map out their tree structures into images and hosted on a very basic html page. Also allows custom querying against the data set when run so you can sift through rules easier.

# TODO:
* Seperate script into seperate logical scripts
* Allow script to itterate over a list of rule files instead of one rule file.
* Add feature to read in decoders (currently it only reads in rules)
* Further enhance reading in rules to create trees based off if_group statements (most trees depend on if_sid statements)
