for F in *.xml; do sed -i "s/TrustAnchor id=\"[^\"]*\"/TrustAnchor id=\"$(uuidgen | tr '[[:lower:]]' '[[:upper:]]')\"/" $F; done
for F in *.xml; do sed -i "s#source=\"[^\"]*\"#source=\"https://localhost/$F\"#" $F; done
