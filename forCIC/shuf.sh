sed -n '/Flow Duration/!p' $1 > temp.txt
gshuf temp.txt > shuf-temp.txt
head -n 1 $1 > temp-header.txt
cat temp-header.txt shuf-temp.txt > shuf-$1.csv
