var request = require('request');
var nodersa = require('node-rsa');
var { v4: uuidv4 } = require('uuid');
var lzstring = require('lz-string');

/*
 * https://nid.naver.com/login/ext/keys.nhn 는 사이트 주소에서 보시다 싶이 key를 가져오는 사이트 입니다.
 * 네이버는 암호화 방법은 rsa, 데이터 인코딩 방법은 bvsd를 사용합니다.
*/

function getLenChar(value) {
  return String.fromCharCode(`${value}`.length); // 문자열의 길이를 ascii 문자로 변경하는 함수입니다.
}

function naver_login(id, pw) {
  console.log('키를 가져오는것을 시도합니다.');
  request('https://nid.naver.com/login/ext/keys.nhn', function (error, response, body) {
    var keyDivision = body.split(',');
    var sessionkey = keyDivision[0];
    var keyname = keyDivision[1];
    var nvalue = keyDivision[2];
    var evalue = keyDivision[3];
    if (sessionkey != undefined && keyname != undefined && nvalue != undefined && evalue != undefined) {
      console.log('키를 찾았습니다!');
      console.log(`sessionkey: ${sessionkey}\nkeyname: ${keyname}\nnvalue: ${nvalue}\nevalue: ${evalue}`);
      console.log('rsa키를 생성하는 중입니다.');
      var rsa = new nodersa();
      rsa.setOptions({encryptionScheme: 'pkcs1'});
      rsa.importKey({
        e: Buffer.from(evalue, 'hex'),
        n: Buffer.from(nvalue, 'hex')
      }, 'components-public');
      console.log(`rsa키가 정상적으로 생성되었습니다. 키: ${rsa.keyPair.n}`);
      console.log('생성한 rsa키로 사용자 정보를 암호화 하는 중입니다.');
      var encpw = rsa.encrypt(`${getLenChar(sessionkey)}${sessionkey}${getLenChar(id)}${id}${getLenChar(pw)}${pw}`, 'hex');
      console.log(`사용자 정보가 성공적으로 암호화 되었습니다. 암호화된 정보: ${encpw}`);
      console.log('랜덤 uuid를 생성하는 중입니다.');
      var uuid = uuidv4();
      console.log(`uuid가 성공적으로 생성 되었습니다. uuid: ${uuid}`);
      console.log('uuid와 각종 정보들을 인코딩 하는중입니다. (bvsddata)');
      var data = `{"a":"${uuid}-4","b":"1.3.4","d":[{"i":"id","b":{"a":["0,${id}"]},"d":"${id}","e":false,"f":false},{"i":"pw","e":true,"f":false}],"h":"1f","i":{"a":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0"}}`;
      var bvsddata = lzstring.compressToEncodedURIComponent(data);
      console.log(`정보가 성공적으로 인코딩 되었습니다. 인코딩된 정보: ${bvsddata}`);
      console.log('bvsd를 생성중입니다.');
      var bvsd = `{"uuid":"${uuid}","encData":"${bvsddata}"}`;
      console.log(`bvsd가 성공적으로 생성 되었습니다. bvsd: ${bvsd}`);
      console.log('마지막으로 네이버에 전송할 데이터를 생성중입니다.');
      var postdata = `localechange=&encpw=${encpw}&enctp=1&svctype=262144&smart_LEVEL=-1&bvsd=${bvsd}&encnm=${keyname}&locale=ko_KR&url=https://www.naver.com&id=&pw=`;
      console.log(`데이터가 성공적으로 생성 되었습니다. data: ${postdata}`);
      console.log('로그인을 시도중입니다.');
      var header = {
        'Referer': 'https://nid.naver.com/nidlogin.login',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
      request({url:'https://nid.naver.com/nidlogin.login', headers:header, body:postdata, method: "POST"}, function (error, response, body) {
        if (body.indexOf('location.replace("') != -1) {
          console.log('로그인에 성공하였습니다.');
        } else {
          console.log('로그인에 실패하였습니다. 비밀번호와 아이디가 틀린것은 없는지 확인하여 주세요.');
        }
      });
      } else {
        console.log('키를 찾지 못하였습니다. 스크립트를 종료합니다.');
        process.exit(1);
      }
  });
}

naver_login('id', 'pw');
