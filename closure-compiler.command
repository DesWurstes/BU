rm -r out
mkdir out
# TODO
cp {qr-code.js,upload.js,utf.min.js,download.js,util.wasm,util.js,bitcore-lib-full.js} out
cp favicon* out
cp icon_big.png out
cp *.html out
cp *.txt out
cp *.xml out
cd out
terser --compress --mangle --warn -o upload.js -- bitcore-lib-full.js qr-code.js utf.min.js util.js upload.js
terser --compress --mangle --warn -o download.js -- utf.min.js util.js download.js
rm utf.min.js qr-code.js bitcore-lib-full.js util.js
sed -i . '/util.js/d' ./upload.html
sed -i . '/utf.min.js/d' ./upload.html
sed -i . '/qr-code.js/d' ./upload.html
sed -i . '/bitcore-lib-full.js/d' ./upload.html
sed -i . '/utf.min.js/d' ./download.html
sed -i . '/util.js/d' ./download.html
HTMLFLAGS="--remove-comments --minify-css true --collapse-inline-tag-whitespace --collapse-whitespace"
# Remove "=" for bash
html-minifier -o download.html download.html ${=HTMLFLAGS}
html-minifier -o examples.html examples.html ${=HTMLFLAGS}
html-minifier -o faq.html faq.html ${=HTMLFLAGS}
html-minifier -o index.html index.html ${=HTMLFLAGS}
html-minifier -o opensource.html opensource.html ${=HTMLFLAGS}
html-minifier -o terms_of_use.html terms_of_use.html ${=HTMLFLAGS}
html-minifier -o upload.html upload.html ${=HTMLFLAGS}
# Then manually fix base href
