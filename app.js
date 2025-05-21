const { createApp, ref } = Vue;

createApp({
  setup() {
    const file = ref(null);
    const key = ref('');
    const downloadUrl = ref('');
    const downloadName = ref('');
    const status = ref('');

    const MAGIC = 'AES_MAGIC:';

    const onFileChange = (event) => {
      file.value = event.target.files[0];
      downloadUrl.value = '';
      downloadName.value = '';
      status.value = '';
    };

    const readFileAsArrayBuffer = () => {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsArrayBuffer(file.value);
      });
    };

    const wordArrayToUint8Array = (wordArray) => {
      const words = wordArray.words;
      const sigBytes = wordArray.sigBytes;
      const u8 = new Uint8Array(sigBytes);
      for (let i = 0; i < sigBytes; i++) {
        u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      }
      return u8;
    };

    const uint8ArrayToWordArray = (u8arr) => {
      const words = [];
      for (let i = 0; i < u8arr.length; i += 4) {
        words.push(
          (u8arr[i] << 24) |
          (u8arr[i + 1] << 16) |
          (u8arr[i + 2] << 8) |
          (u8arr[i + 3])
        );
      }
      return CryptoJS.lib.WordArray.create(words, u8arr.length);
    };

    const encrypt = async () => {
      try {
        status.value = '🔒 Đang mã hóa...';

        const buffer = await readFileAsArrayBuffer();
        const u8 = new Uint8Array(buffer);

        // Thêm MAGIC prefix
        const magicBytes = new TextEncoder().encode(MAGIC);
        const merged = new Uint8Array(magicBytes.length + u8.length);
        merged.set(magicBytes);
        merged.set(u8, magicBytes.length);

        const data = uint8ArrayToWordArray(merged);

        const aesKey = CryptoJS.SHA256(key.value);
        const iv = CryptoJS.lib.WordArray.random(16);

        const encrypted = CryptoJS.AES.encrypt(data, aesKey, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        });

        const result = iv.concat(encrypted.ciphertext);
        const resultBytes = wordArrayToUint8Array(result);
        const blob = new Blob([resultBytes], { type: 'application/octet-stream' });

        downloadUrl.value = URL.createObjectURL(blob);
        downloadName.value = file.value.name + '.enc';
        status.value = '✅ Mã hóa thành công!';
      } catch (err) {
        status.value = '❌ Lỗi mã hóa: ' + err.message;
      }
    };

    const decrypt = async () => {
      try {
        status.value = '🔓 Đang giải mã...';
        const buffer = await readFileAsArrayBuffer();
        const data = new Uint8Array(buffer);

        const iv = CryptoJS.lib.WordArray.create(data.slice(0, 16));
        const ciphertext = CryptoJS.lib.WordArray.create(data.slice(16));
        const aesKey = CryptoJS.SHA256(key.value);

        const decrypted = CryptoJS.AES.decrypt(
          { ciphertext },
          aesKey,
          {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
          }
        );

        const u8 = wordArrayToUint8Array(decrypted);

        // Kiểm tra MAGIC prefix
        const magicBytes = new TextEncoder().encode(MAGIC);
        const magicLength = magicBytes.length;

        const match = magicBytes.every((b, i) => u8[i] === b);
        if (!match) throw new Error('Sai khóa hoặc file không hợp lệ.');

        const clean = u8.slice(magicLength);
        const blob = new Blob([clean], { type: 'application/octet-stream' });
        const originalName = file.value.name.replace(/\.enc$/, '') || 'decrypted.bin';

        downloadUrl.value = URL.createObjectURL(blob);
        downloadName.value = originalName;
        status.value = '✅ Giải mã thành công!';
      } catch (err) {
        downloadUrl.value = '';
        downloadName.value = '';
        status.value = '❌ Lỗi giải mã: ' + err.message;
      }
    };

    return {
      file, key, downloadUrl, downloadName,
      status, onFileChange, encrypt, decrypt
    };
  }
}).mount('#app');
