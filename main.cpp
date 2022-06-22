// Khang Nguyen
// Project 2 - CSCE 3550.001
// Due 11-9-2021
// This is an implementation of a simple encryption system that takes in plaintext from a file and
// decrypts it using a simplified version of AES (Advanced Encryption System).

#include <iostream>
#include <fstream>
#include <string>
#include <math.h>

using namespace std;

int rgfMul(int x, int y) //function to compute x*2 and x*3 for Rijndaels Galois field. x = our number and y = 2 or 3
{
    int oldx = x; //keep old x

    //Step 1 - Check to see if x's MSB is set. Since we are using 8 bit binary, shifting x >> 7 will result in 0000 0001 if the MSB was 1.
    //We then check to see if x>>7 == 1. If x>>7 !=1, the MSB was not set.
    if (y == 2 || y == 3) //multiply by 2 (if we multiply by 3 we also need to multiply by 2)
    {
        //then check to see if x's MSB was set prior to shifting left
        if ((x >> 7) == 1)
        {
            x <<= 1;  //shift x left by 1
            x -= 256; //subtract 256 to get rid of set bit that is in position 2^8
            x ^= 27;  //x XOR with 27 in decimal or 0001 1011 in binary
        }
        else
        {
            x <<= 1; //shift x left by 1
        }
    }

    if (y == 3) //multiply by 3, XOR x*2 with original x
    {
        x ^= oldx; //XOR x with oldx
    }

    return x; //return answer
}

int main()
{

    string inputfile;  //file of the input
    string keyfile;    //file of the key
    string outputfile; //file of the output

    cout << "Enter the name of the input plaintext file: "; //prompt user to enter plaintext file
    cin >> inputfile;

    cout << "Enter the name of the input key file: "; //prompt user to enter input key file
    cin >> keyfile;

    cout << "Enter the name of the output ciphertext file: "; //prompt user to enter the output file
    cin >> outputfile;

    ifstream fin;  //for reading in
    ofstream fout; //for writing out

    //Get Key from key.txt file
    string key;
    fin.open(keyfile);
    if (fin.is_open())
    {
        getline(fin, key);
    }
    fin.close();

    fin.open(inputfile); //opens plaintext file
    if (fin.is_open())
    {
        //str below takes in 2 parameters: str(starting iterator, end iterator)
        //a default istreambuf_uterator<char>() is an end-of-file iterator (it points to the end of the file). We will compare the first iterator to this to see if it has reached the eof.
        //istreambuf_iterator<char>(fin) takes in "fin" which causes it to read in every char in the file and increments until the iterator equals istreambuf_uterator<char>(), once it does equal, it has reached oef so its done.
        string str((istreambuf_iterator<char>(fin)), (istreambuf_iterator<char>())); //reads in entire file as 1 single string

        //--Preprocessing Step 1--//
        int length;                                           //length of the entire file as a string
        for (int i = 0, length = str.size(); i < length; i++) //length will be dynamically changed as it loops
        {
            if (ispunct(str[i]) || isspace(str[i])) //check if that char in str[i] is either a punctuation or a space
            {
                str.erase(i--, 1);   //erase(pos of char to erase, length of char ot erase). We give i-- as pos b/c we are ahead in index by 1.
                length = str.size(); //redefine the new str length after deleting 1 char.
            }
        }

        //display Preprocessing step in terminal and write into file
        cout << "Preprocessing:" << endl;
        cout << str << endl;
        cout << endl;

        fout.open(outputfile); //open output file
        if (fout.is_open())
        {
            fout << "Preprocessing:" << endl;
            fout << str << endl;
            fout << endl;
        }

        //--Substitution Step 2--//
        int keyarray[16]; //make an array to hold the key. We will iterate through for our vignere cipher
        for (int i = 0; i < 16; i++)
        {
            keyarray[i] = key[i]; //assign individual char in the key string to the array
        }

        //Vignere Cipher adding
        string cipherstring; //string to hold the ciphered text
        for (int i = 0; i < str.length(); i++)
        {
            int ascNum = (str[i] + keyarray[i % 16]) % 26; //we add the char from our key and the char from out input to get out ascii number.
            //keyarray has [i%16] so that it loops while the str keeps going. We also mod % by 26 to loop through the alphabet.
            cipherstring.push_back(char(ascNum + 65)); //we add 65 because A starts at ascii #65
        }

        //displaying Substitution step in terminal and write into file
        cout << "Substitution:" << endl;
        cout << cipherstring << endl;
        cout << endl;

        if (fout.is_open())
        {
            fout << "Substitution:" << endl;
            fout << cipherstring << endl;
            fout << endl;
        }

        //--Padding Step 3--//
        int numDiv = cipherstring.length() % 16; //take the length of the cipher string and divide by 16.
        if (numDiv != 0)                         // if answer is != 0, the cipher string is not evenly divisible by 16, so we need to pad.
        {

            int padNum = 16 - numDiv; //the number of A's needed to pad the cipher text so that it is evenly divisible by 16. I subtract numDiv from 16 to see how many more A's I need to reach the next highest multiple of 16.
            for (int i = 0; i < padNum; i++)
            {
                cipherstring += "A"; //append a to my cipherstring
            }
        }

        string blockarray[cipherstring.length() / 4]; //array to hold the block lines. Take cipher length and divide by 4 to see how many lines we need

        //displaying Padding step in terminal and write into file
        cout << "Padding:" << endl;
        string block;                                       //string to hold the blocks of chars
        int counter = 0;                                    //counter to determine when a block is full
        int blockcounter = 0;                               //counter to determine the spaces between blocks
        for (int i = 0; i < cipherstring.length() + 1; i++) //iterate until cipherstring.length()+1 b/c I need to iterate 1 last time to print the last block.
        {
            if (counter < 4) //if block still has < 4 chars, concatenate
            {
                block += cipherstring[i]; //concatenate to block string
                counter++;                //increase counter
            }
            else //else if the block has 4 chars, display and reset block string
            {
                cout << block << endl;            //display block string and endl
                blockarray[blockcounter] = block; //pass in block string to blockstring array
                blockcounter++;                   //increase # of blocks in counter
                if ((blockcounter % 4) == 0)      //add space between blocks in groups of 4
                {
                    cout << endl;
                }
                block = "";               //empty block string for use again
                block += cipherstring[i]; //concatenate to account for the char on index i in cipherstring when counter = 4
                counter = 1;              //reset the counter again (we reset at 1 since we accounted for a char in the above line)
            }
        }

        //write into file
        if (fout.is_open())
        {
            int blockcounter = 0;
            fout << "Padding:" << endl;
            for (int i = 0; i < cipherstring.length() / 4; ++i)
            {
                fout << blockarray[i] << endl;
                blockcounter++;
                if ((blockcounter % 4) == 0)
                {
                    if (i != 0)
                    {
                        fout << endl;
                    }
                }
            }
        }

        //--ShiftRows Step 4--//
        cout << "ShiftRows: " << endl;
        string stringshift;                             //string to be shifted
        string shiftedblock[cipherstring.length() / 4]; //array to hold the shifted block lines.
        int blockcounter1 = 0;

        for (int i = 0; i < cipherstring.length() / 4; ++i)
        {
            stringshift = blockarray[i]; //assign block line to this string variable to shift.
            if ((i % 4) == 0)            //first line in block of 4
            {
                cout << stringshift << endl;
                shiftedblock[i] = stringshift; //assign shiftedblock array with shifted string
                blockcounter1++;
            }
            else if ((i % 4) == 1) //second line in block of 4
            {
                char temp = stringshift[0];                        //save first char
                for (int i = 0; i < stringshift.length() - 1; ++i) //iterate up to 3 times
                {
                    stringshift[i] = stringshift[i + 1];
                }
                stringshift[3] = temp;         //replace last char with first char
                cout << stringshift << endl;   //print line shifted left by 1
                shiftedblock[i] = stringshift; //assign shiftedblock array with shifted string
                blockcounter1++;
            }
            else if ((i % 4) == 2) //third line in block of 4
            {
                char temp = stringshift[0];                        //save first char
                char temp1 = stringshift[1];                       //save second char
                for (int i = 0; i < stringshift.length() - 2; ++i) //iterate up to 2 times
                {
                    stringshift[i] = stringshift[i + 2];
                }
                stringshift[2] = temp;         //replace third char with first char
                stringshift[3] = temp1;        //replace fourth char with second char
                cout << stringshift << endl;   //print line shifted left by 2
                shiftedblock[i] = stringshift; //assign shiftedblock array with shifted string
                blockcounter1++;
            }
            else if ((i % 4) == 3) //fourth line in block of 4
            {
                char temp = stringshift[0];                        //save first char
                char temp1 = stringshift[1];                       //save second char
                char temp2 = stringshift[2];                       //save third char
                for (int i = 0; i < stringshift.length() - 1; ++i) //iterate up to 2 times
                {
                    stringshift[i] = stringshift[i + 3];
                }
                stringshift[1] = temp;         //replace second char with first char
                stringshift[2] = temp1;        //replace third char with second char
                stringshift[3] = temp2;        //replace fourth char with third char
                cout << stringshift << endl;   //print line shifted left by 3
                shiftedblock[i] = stringshift; //assign shiftedblock array with shifted string
                blockcounter1++;
            }

            if (blockcounter1 % 4 == 0) //add space between blocks
            {
                if (i != 0)
                {
                    cout << endl;
                }
            }
        }

        //write into file
        if (fout.is_open())
        {
            int blockcounter = 0;
            fout << "ShiftRows:" << endl;
            for (int i = 0; i < cipherstring.length() / 4; ++i)
            {
                fout << shiftedblock[i] << endl;
                blockcounter++;
                if ((blockcounter % 4) == 0)
                {
                    if (i != 0)
                    {
                        fout << endl;
                    }
                }
            }
        }

        //--Parity Bit Step 5--//p
        int hexedarray[(cipherstring.length() / 4)][4]; //2d array to hold hexed numbers in decimal form

        if (fout.is_open())
        {
            cout << "Parity Bit: " << endl;
            fout << "Parity Bit: " << endl;

            string stringparity; //string to be parity(ed)
            char hexstring[20];  //char array to hold hexadecimal string to be printed in C using %X

            unsigned int bitcount; //counter to count the number of bits
            for (int i = 0; i < cipherstring.length() / 4; ++i)
            {
                stringparity = shiftedblock[i]; //assign temp string with block string from array
                for (int j = 0; j < 4; ++j)     //loop through string itself
                {
                    bitcount = 0;                   //reset bitcount for each char
                    int ascNum = (stringparity[j]); //convert char to ASCII value (no need to add 65)
                    //cout << "ascNum :" << ascNum << endl;

                    for (int k = 0; k < 8; ++k) //we iterate 8 times for 8 bit binary
                    {
                        if (((ascNum >> k) & 1) == 1) //shift by k and compare rightmost bit ANDed with 1 to see if it is set
                        {
                            bitcount++; //increase bitcount by 1
                        }
                    }
                    //cout << bitcount << endl;

                    if (bitcount % 2 == 0) //if bitcount is EVEN
                    {
                        hexedarray[i][j] = ascNum;        //assign ascNum to hexedarray in decimal form
                        sprintf(hexstring, "%x", ascNum); //convert number to hexadecimal
                        cout << hexstring << " ";
                        fout << hexstring << " ";
                    }
                    else //if bitcount is ODD, set MSB (we set 8th bit from the left to a 1, so its same as adding 2^8 to the number)
                    {
                        ascNum += pow(2, 7);              //add 2^7 to number, this is the same as setting the MSB to 1.
                        hexedarray[i][j] = ascNum;        //assign ascNum to hexedarray in decimal form
                        sprintf(hexstring, "%x", ascNum); //convert number to hexadecimal
                        cout << hexstring << " ";
                        fout << hexstring << " ";
                    }
                }
                cout << endl;
                fout << endl;
            }
        }

        //--Mix Columns Step 6--//
        int rgfArray[(cipherstring.length() / 4)][4]; //array to hold the multiplied values
        int row = 0;                                  //variable to hold row value
        int temparray[4][4];                          //temp array to hold a block

        //temp varaibles for rgf matrix multiplcation
        int temp1 = 0;
        int temp2 = 0;
        int temp3 = 0;
        int temp4 = 0;

        int blockcounter2 = 0;                              //counter for block spacing
        for (int i = 0; i < cipherstring.length() / 4; ++i) //loop through array holding hexed values
        {
            for (int j = 0; j < 4; ++j)
            {
                temparray[i % 4][j] = hexedarray[i][j]; //put numbers into temp array
            }
            blockcounter2++;            //after the for loop above, increase block counter
            if (blockcounter2 % 4 == 0) //if this is the end of a block
            {
                for (int i = 0; i < 4; ++i) //matrix multiplication
                {
                    //multiply each column in our block with Galois Field matrix
                    temp1 = rgfMul(temparray[0][i], 2) ^ rgfMul(temparray[1][i], 3) ^ temparray[2][i] ^ temparray[3][i];
                    temp2 = temparray[0][i] ^ rgfMul(temparray[1][i], 2) ^ rgfMul(temparray[2][i], 3) ^ temparray[3][i];
                    temp3 = temparray[0][i] ^ temparray[1][i] ^ rgfMul(temparray[2][i], 2) ^ rgfMul(temparray[3][i], 3);
                    temp4 = rgfMul(temparray[0][i], 3) ^ temparray[1][i] ^ temparray[2][i] ^ rgfMul(temparray[3][i], 2);

                    //save each value in our new array
                    rgfArray[row + 0][i] = temp1;
                    rgfArray[row + 1][i] = temp2;
                    rgfArray[row + 2][i] = temp3;
                    rgfArray[row + 3][i] = temp4;
                }
                row = row + 4; //every new block will need to iterate at a row that is 4 rows ahead of the previous
            }
        }

        cout << endl;

        //display and write to file
        if (fin.is_open())
        {
            fout << endl;
            cout << "MixColumns:" << endl;
            fout << "MixColumns:" << endl;
            for (int i = 0; i < cipherstring.length() / 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    char hexstring[20];                       //char array to hold hexadecimal
                    sprintf(hexstring, "%x", rgfArray[i][j]); //convert to hex and store in hexstring
                    cout << hexstring << " ";
                    fout << hexstring << " ";
                }
                cout << endl;
                fout << endl;
            }
        }

        fin.close(); //close output file
    }
    else
    {
        cout << "No input file detected. Please try again." << endl; //error message
    }
    fin.close();

    return 0;
}