import NodeClam from "clamscan";
import axios from 'axios'

const clamscan = await new NodeClam().init({
    clamdscan: {
        host: '127.0.0.1',
        port: 3310
    }
});

clamscan.getVersion((err, version) => {
    if (err) return console.error(err);
    console.log(`ClamAV Version: ${version}`);
});

const checkVirus = async (url) => {
    
    return new Promise(async (resolve, reject) => {
        try {
            const response = await axios.get(url, {
                responseType: 'stream'
            }); 
    
            const resData = response.data;
            const av = clamscan.passthrough();
            resData.pipe(av);
    
            av.on('scan-complete', result => {
                console.log('scan-complete');
                const { isInfected, viruses } = result;
                console.log(isInfected, viruses);
    
                resolve({isInfected: isInfected, viruses: viruses})
             });
            
        } catch(e) {
            reject(e);
        } 
    })

}

//Insert a file URL for virus scanning
const result = await checkVirus('https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf'); 
console.log('result', result);