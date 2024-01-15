
for name in $(find . -type l -name "modules-*"); do
    tgt=`readlink "$name"`
    ln -f -s ../$tgt $name
done




