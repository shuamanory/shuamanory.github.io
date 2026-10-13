(() => {
  // ns-hugo-imp:/Users/shua/Library/Caches/hugo_cache/modules/filecache/modules/pkg/mod/github.com/hugomods/snackbar@v0.1.2/assets/mods/snackbar/js/index.ts
  var Snackbar = class {
    container;
    constructor() {
      this.container = document.createElement("div");
      this.container.className = "snackbars";
      document.body.appendChild(this.container);
    }
    add(text, duration = 2e3) {
      const msg = document.createElement("div");
      msg.className = "snackbar";
      msg.innerText = text;
      this.container.appendChild(msg);
      setTimeout(() => {
        msg.remove();
      }, duration);
    }
  };
  var snackbar = new Snackbar();
  var js_default = snackbar;

  // ns-hugo-params:/Users/shua/Library/Caches/hugo_cache/modules/filecache/modules/pkg/mod/github.com/hugomods/encrypt@v0.4.0/assets/mods/encrypt/js/decryptor.ts
  var decryptor_default = { storage: "session" };

  // ns-hugo-imp:/Users/shua/Library/Caches/hugo_cache/modules/filecache/modules/pkg/mod/github.com/hugomods/encrypt@v0.4.0/assets/mods/encrypt/js/decryptor.ts
  var Decryptor = class {
    /**
     * Encodes a utf8 string as a byte array.
     * @param {string} str
     * @returns {Uint8Array}
     */
    str2buf(str) {
      return new TextEncoder().encode(str);
    }
    /**
     * Decodes a byte array as a utf8 string.
     * @param {Uint8Array} buffer
     * @returns {string}
     */
    buf2str(buffer) {
      return new TextDecoder("utf-8").decode(buffer);
    }
    /**
     * Decodes a string of hex to a byte array.
     * @param {string} hexStr
     * @returns {Uint8Array}
     */
    hex2buf(hexStr) {
      return new Uint8Array(hexStr.match(/.{2}/g).map((h) => parseInt(h, 16)));
    }
    /**
     * Given a passphrase, this generates a crypto key
     * using `PBKDF2` with SHA256 and 1000 iterations.
     * If no salt is given, a new one is generated.
     * The return value is an array of `[key, salt]`.
     * @param {string} passphrase
     * @param {UInt8Array} salt [salt=random bytes]
     * @returns {Promise<[CryptoKey,UInt8Array]>}
     */
    async deriveKey(passphrase, salt) {
      salt = salt ?? crypto.getRandomValues(new Uint8Array(8));
      return await crypto.subtle.importKey("raw", this.str2buf(passphrase), "PBKDF2", false, [
        "deriveKey"
      ]).then(
        async (key) => await crypto.subtle.deriveKey(
          { name: "PBKDF2", salt, iterations: 1e3, hash: "SHA-256" },
          key,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        )
      ).then((key) => [key, salt]);
    }
    decryptBlock(block, password = "") {
      if (password === "") {
        const passwordEl = block.querySelector("input");
        password = passwordEl.value;
      }
      if (password === "") {
        return;
      }
      const content = block.querySelector(".hugo-encrypt-content");
      this.decrypt(password, content.innerText).then((plaintext) => {
        this.digestMessage(plaintext.replace(/\r?\n?[^\r\n]*$/, "")).then((sum) => {
          if (plaintext.includes(sum)) {
            content.innerHTML = plaintext;
            block.classList.add("decrypted");
            this.rememberPassword(
              block.getAttribute("data-id") ?? "",
              password
            );
          }
        }).catch((err) => {
          throw err;
        });
      }).catch((err) => {
        js_default.add(block.getAttribute("data-error-msg"));
        this.clearPassword(block.getAttribute("data-id") ?? "");
        console.log(err);
      });
    }
    storage() {
      return decryptor_default.storage === "session" ? sessionStorage : localStorage;
    }
    cacheKey(id) {
      return `hugo-encrypt-password-${location.pathname}-${id}`;
    }
    rememberPassword(id, password) {
      this.storage().setItem(this.cacheKey(id), password);
    }
    clearPassword(id) {
      this.storage().removeItem(this.cacheKey(id));
    }
    recover(block) {
      const id = block.getAttribute("data-id");
      if (id === null || id === void 0) {
        return;
      }
      const pwd = this.storage().getItem(this.cacheKey(id));
      if (pwd !== null) {
        this.decryptBlock(block, pwd);
      }
    }
    /**
     * Given a key and ciphertext (in the form of a string) as given by `encrypt`,
     * this decrypts the ciphertext and returns the original plaintext
     * @param {string} passphrase
     * @param {string} saltIvCipherHex
     * @returns {Promise<string>}
     */
    async decrypt(passphrase, saltIvCipherHex) {
      const [salt, iv, data] = saltIvCipherHex.split("-").map(this.hex2buf);
      return await this.deriveKey(passphrase, salt).then(
        async ([key]) => await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data)
      ).then((v) => this.buf2str(new Uint8Array(v)));
    }
    /**
     * @name: digestMessage
     * @description: hashing string
     * @param {string} message
     * @returns {Promise<string>}
     */
    async digestMessage(message) {
      const msgUint8 = new TextEncoder().encode(message);
      const hashBuffer = await crypto.subtle.digest("SHA-1", msgUint8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
      return hashHex;
    }
  };
  var decryptor_default2 = Decryptor;

  // <stdin>
  (() => {
    document.addEventListener("DOMContentLoaded", () => {
      const decryptor = new decryptor_default2();
      const buttons = document.querySelectorAll(".hugo-decrypt-button");
      buttons.forEach((btn) => {
        const block = btn.closest(".hugo-encrypt");
        decryptor.recover(block);
        btn.addEventListener("click", () => {
          decryptor.decryptBlock(block);
        });
      });
    });
  })();
})();
