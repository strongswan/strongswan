# script to clean up HTML files
# removes formatting added by htmldoc
#
# first argument is sedscript to use
f=$1
shift
# remaining args are files to process
for i
do
	sed -f $f $i > tmp
	mv tmp $i
done
