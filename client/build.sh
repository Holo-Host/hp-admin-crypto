set -e

wasm-pack build --scope holo-host
wasm-pack build --scope holo-host --out-dir pkg-nodejs --target nodejs

PACKAGE_NAME=$(basename $(jq -r .name pkg/package.json | tr - _))

sed "s/${PACKAGE_NAME}_bg.wasm/${PACKAGE_NAME}.wasm/" pkg-nodejs/${PACKAGE_NAME}.js > pkg/${PACKAGE_NAME}_node.js
cp pkg-nodejs/${PACKAGE_NAME}_bg.wasm pkg/${PACKAGE_NAME}.wasm
cp pkg-nodejs/${PACKAGE_NAME}_bg.wasm.d.ts pkg/${PACKAGE_NAME}.wasm.d.ts

PACKAGE_JQ_FILTER=$(cat <<END
.files += ["${PACKAGE_NAME}_bg.wasm.d.ts", "${PACKAGE_NAME}.wasm"] | .main = "${PACKAGE_NAME}_node.js"
END
)

jq "$PACKAGE_JQ_FILTER" pkg/package.json > pkg/package.json.tmp
mv pkg/package.json.tmp pkg/package.json

rm -r pkg-nodejs
