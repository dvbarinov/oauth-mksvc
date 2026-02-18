import crypto from 'crypto';
//import { JWK } from 'jsonwebtoken'; // Типы, если нужно, но будем использовать crypto напрямую

let privateKey: string;
let publicKey: string;
let jwk: any; // JSON Web Key представление

export const initKeys = () => {
  // Генерируем пару ключей RSA 2048 бит
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  privateKey = priv;
  publicKey = pub;

  // Преобразуем публичный ключ в формат JWK для стандарта JWKS
  // Это немного сложно вручную, поэтому используем хак с созданием dummy токена и его разбором, 
  // либо библиотеку node-rsa/jose. Но для простоты сделаем парсинг PEM -> JWK вручную или через утилиту.
  
  // Простой способ получить JWK из PEM через crypto (Node 15+) требует extra steps.
  // Для надежности в реальном проекте используйте библиотеку `jose`.
  // Здесь реализуем упрощенный вариант создания JWK объекта.
  
  const keyObject = crypto.createPublicKey(pub);
  const jwkObj = keyObject.export({ format: 'jwk' });
  
  jwk = {
    ...jwkObj,
    alg: 'RS256',
    use: 'sig',
    kid: 'oauth-server-key-1' // Key ID, должен совпадать в заголовке токена
  };

  console.log('✅ RSA Keys generated successfully');
};

export const getPrivateKey = () => privateKey;
export const getPublicKeyJwk = () => jwk;