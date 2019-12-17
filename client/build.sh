set -e

wasm-pack build --scope holo-host
wasm-pack build --scope holo-host --out-dir pkg-nodejs --target nodejs

PACKAGE_NAME=$(basename $(jq -r .name pkg/package.json | tr - _))

cp pkg-nodejs/${PACKAGE_NAME}.js pkg/${PACKAGE_NAME}_node.js

sed "s/${PACKAGE_NAME}.js')/${PACKAGE_NAME}_node.js')/" \
  pkg-nodejs/${PACKAGE_NAME}_bg.js > pkg/${PACKAGE_NAME}_bg.js

PACKAGE_JQ_FILTER=$(cat <<END
.files += ["${PACKAGE_NAME}_bg.js"] | .main = "${PACKAGE_NAME}_node.js"
END
)

jq "$PACKAGE_JQ_FILTER" pkg/package.json > pkg/package.json.tmp
mv pkg/package.json.tmp pkg/package.json

rm -r pkg-nodejs
