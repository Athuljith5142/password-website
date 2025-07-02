function clears(){
let text = document.getElementById('t1');

text.value=" ";
}
const passwordbox = document.getElementById('t1');
const length = 12 ;

const uppercases = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const lowercases = 'abcdefghijklmnopqrstuvwxyz';
const numbers = '0123456789';
const symbols = '"@!#$%^&*_-=';

const allchar = uppercases+lowercases+numbers+symbols;
function pass(){
    let password ="";
    password += uppercases[Math.floor(Math.random() * uppercases.length)];
    password += lowercases[Math.floor(Math.random() * lowercases.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];



    while(length > password.length){
    password += allchar[Math.floor(Math.random() * allchar.length)];    
    }


    passwordbox.value= password;
}

function takes(){
   passwordbox.select();
   document.execCommand("copy"); 
}

