import { HpAdminKeypair } from "../../pkg";

const HC_PUBLIC_KEY = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
const EMAIL = "pj@abba.pl";
const PASSWORD = "abba";

let kp = new HpAdminKeypair(HC_PUBLIC_KEY, EMAIL, PASSWORD);

const payload = {
    method: "get",
    request: "/someuri",
    body: undefined
}

console.log(kp.sign(payload));
