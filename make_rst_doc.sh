#!/bin/sh

make doc
rm -rf doc/rst && mkdir doc/rst

for Mod in leo_s3_auth \
           leo_s3_bucket \
           leo_s3_bucket_data_handler \
           leo_s3_bucket_data_handler \
           leo_s3_endpoint \
           leo_s3_libs \
           leo_s3_libs_data_handler \
           leo_s3_user \
           leo_s3_user_credential
do
    read_file="doc/$Mod.html"
    write_file="doc/rst/$Mod.rst"

    pandoc --read=html --write=rst "$read_file" -o "$write_file"

    sed -ie "1,6d" "$write_file"
    sed -ie "1s/\Module //" "$write_file"
    LINE_1=`cat $write_file | wc -l`
    LINE_2=`expr $LINE_1 - 10`
    sed -ie "$LINE_2,\$d" "$write_file"
done
rm -rf doc/rst/*.rste
