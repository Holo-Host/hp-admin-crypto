# The purpose of this builder script is to create a package for npm that
# can be used in both browser and nodejs context.
# Both versions of .wasm and .js bindings are build in two separate steps,
# then results are merged.
set -e

# build browser version of the package into pkg directory
wasm-pack build --scope holo-host
# build nodejs version of the package into pkg-nodejs directory
wasm-pack build --scope holo-host --out-dir pkg-nodejs --target nodejs

PACKAGE_NAME=$(basename $(jq -r .name pkg/package.json | tr - _))

# .wasm files for browser and nodejs are not the same, therefore we need
# to include both in the package published on npm

# update names of nodejs .wasm file in nodejs bindings file
sed "s/${PACKAGE_NAME}_bg.wasm/${PACKAGE_NAME}.wasm/" pkg-nodejs/${PACKAGE_NAME}.js > pkg/${PACKAGE_NAME}_node.js

# copy nodejs .wasm to final directory
cp pkg-nodejs/${PACKAGE_NAME}_bg.wasm pkg/${PACKAGE_NAME}.wasm
cp pkg-nodejs/${PACKAGE_NAME}_bg.wasm.d.ts pkg/${PACKAGE_NAME}.wasm.d.ts

# add copied files to package.json, otherwise `wasm-pack publish` won't include them in the package
PACKAGE_JQ_FILTER=$(cat <<END
.files += ["${PACKAGE_NAME}_bg.wasm.d.ts", "${PACKAGE_NAME}.wasm"] | .main = "${PACKAGE_NAME}_node.js"
END
)
jq "$PACKAGE_JQ_FILTER" pkg/package.json > pkg/package.json.tmp
mv pkg/package.json.tmp pkg/package.json

rm -r pkg-nodejs
