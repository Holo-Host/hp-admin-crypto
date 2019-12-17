import { HpAdminKeypair } from "@holo-host/hp-admin-key-manager";

const HC_PUBLIC_KEY = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
const EMAIL = "pj@abba.pl";
const PASSWORD = "abba";

let kp = new HpAdminKeypair(HC_PUBLIC_KEY, EMAIL, PASSWORD);

const payload = {
    method: "get",
    uri: "/someuri",
    body_string: ""
}

console.log(kp.sign(payload));
