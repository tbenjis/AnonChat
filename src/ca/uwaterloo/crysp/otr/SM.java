/*
 *  Java OTR library
 *  Copyright (C) 2008-2009  Ian Goldberg, Muhaimeen Ashraf, Andrew Chung,
 *                           Can Tang
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package ca.uwaterloo.crysp.otr;

import ca.uwaterloo.crysp.otr.crypt.*;

class SMState{
	MPI secret, x2, x3, g1, g2, g3, g3o, p, q, pab, qab;
	int nextExpected;
	int receivedQuestion;
	int smProgState;
	
	public SMState(){
		g1 = new MPI(SM.GENERATOR_S);
		smProgState = SM.PROG_OK;
	}
}

public class SM {
	
	public static final int EXPECT1 = 0;
	public static final int EXPECT2 = 1;
	public static final int EXPECT3 = 2;
	public static final int EXPECT4 = 3;
	public static final int EXPECT5 = 4;
	
	public static final int PROG_OK = 0;
	public static final int PROG_CHEATED = -2;
	public static final int PROG_FAILED = -1;
	public static final int PROG_SUCCEEDED = 1;

	public static final int MSG1_LEN = 6;
	public static final int MSG2_LEN = 11;
	public static final int MSG3_LEN = 8;
	public static final int MSG4_LEN = 3;
	
	public static final byte[] MODULUS_S = Util.hexStringToBytes(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF");
	
	public static final byte[] MODULUS_MINUS_2 = Util.hexStringToBytes(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFD");
	
	public static final byte[] ORDER_S = Util.hexStringToBytes(
			"7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68"+
		    "948127044533E63A0105DF531D89CD9128A5043CC71A026E"+
		    "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122"+
		    "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6"+
		    "F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E"+
		    "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF"+
		    "C1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36"+
		    "B3861AA7255E4C0278BA36046511B993FFFFFFFFFFFFFFFF");
	
	public static final byte[] GENERATOR_S = Util.hexStringToBytes("02");
	public static final int MOD_LEN_BITS = 1536;
	public static final int MOD_LEN_BYTES = 192;
	
	
	/** Generate a random exponent */
	public static MPI randomExponent(Provider prov){
		SecureRandom sr = prov.getSecureRandom();
		byte[] sb = new byte[MOD_LEN_BYTES];
		sr.nextBytes(sb);
		return new MPI(sb);
	}
	
	/**
	 * Hash one or two MPIs.  To hash only one MPI, b may be set to NULL.
	 */
	public static MPI hash(int version, MPI a, MPI b, Provider prov) throws OTRException
	{
		int totalsize = 1 + 4 + a.getLength();
		if(b!=null){
			totalsize+= 4 + b.getLength();
		}
	    byte[] buf = new byte[totalsize];
	    OutBuf obuf = new OutBuf(buf);
	    
	    obuf.writeByte((byte)version);
	    obuf.writeUInt(a.getLength());
	    a.writeRaw(obuf);

	    if (b!=null) {
	    	obuf.writeUInt(b.getLength());
	    	b.writeRaw(obuf);
	    }
	    byte[] out = obuf.getBytes();
	    SHA256 sha = prov.getSHA256();
	    byte[] digest = sha.hash(out);
	    return new MPI(digest);
	}
	
	/** This method accepts an array of MPIs, and returns a byte array
	 * containing a reversible serialization. 
	 * @throws OTRException */
	public static byte[] serializeMPIArray(MPI[] mpis) throws OTRException
	{
		int totalsize=0;
	    for (int i=0; i<mpis.length; i++) {
	        totalsize += 4+mpis[i].getLength();
	    }

	    totalsize+=4;
	    byte[] buf = new byte[totalsize];
	    OutBuf obuf = new OutBuf(buf);
	    obuf.writeUInt(mpis.length);
	    
	    for(int i=0; i<mpis.length; i++)
	    {
	        mpis[i].write(obuf);
	    }
	    return obuf.getBytes();
	}
	
	/** Takes a byte array containing serialized and concatenated MPIs
	 * and converts it to an array of MPIs.
	 * The buffer is assumed to consist of a 4-byte int containing the
	 * number of MPIs in the array, followed by {size, data} pairs for
	 * each MPI.
	 * @throws OTRException */
	public static MPI[] unserializeMPIArray(byte[] buffer) throws OTRException
	{
	    InBuf ibuf = new InBuf(buffer);

	    int count = (int)ibuf.readUInt();
	    
	    if(count<=0) throw new OTRException("Invalid count");

	    MPI[] mpis = new MPI[count];

	    for (int i=0; i<count; i++) {
	    	mpis[i]=MPI.readMPI(ibuf);
	    }

	    return mpis;
	}
	
	/** Check that an MPI is in the right range to be a (non-unit) group
	 * element */
	public static boolean checkGroupElem(MPI g, Provider prov)
	{
		byte[] two = {2};
	    if (prov.compareMPI(g, new MPI(two)) < 0 || 
	    		prov.compareMPI(g, new MPI(SM.MODULUS_MINUS_2)) > 0){
	    	return true;
	    }
	    return false;
	}
	
	/** Check that an MPI is in the right range to be a (non-zero) exponent */
	public static boolean checkExpon(MPI x, Provider prov)
	{
		byte[] one={1};
	    if (prov.compareMPI(x,new MPI(one))<0 ||
	    		prov.compareMPI(x, new MPI(SM.ORDER_S))>=0) {
	    	return true;
	    }
	    return false;
	}
	
	/**
	 * Proof of knowledge of a discrete logarithm
	 * @throws OTRException 
	 */
	public static MPI[] proofKnowLog(MPI g, MPI x, int version, Provider prov) throws OTRException
	{
	    MPI r = randomExponent(prov);
	    MPI temp = prov.powm(g, r, new MPI(MODULUS_S));
	    MPI c = hash(version, temp, null, prov);
	    temp = prov.mulm(x, c, new MPI(ORDER_S));
	    MPI d = prov.subm(r, temp, new MPI(ORDER_S));
	    MPI[] ret = new MPI[2];
	    ret[0]=c;
	    ret[1]=d;
	    return ret;
	}
	
	/**
	 * Verify a proof of knowledge of a discrete logarithm.  Checks that c = h(g^d x^c)
	 * @throws OTRException 
	 */
	public static int checkKnowLog(MPI c, MPI d, MPI g, MPI x, int version, Provider prov) throws OTRException
	{

	    MPI gd = prov.powm(g, d, new MPI(MODULUS_S));
	    MPI xc = prov.powm(x, c, new MPI(MODULUS_S));
	    MPI gdxc = prov.mulm(gd, xc, new MPI(MODULUS_S));
	    MPI hgdxc = hash(version, gdxc, null, prov);
	    
	    return prov.compareMPI(hgdxc, c);
	}
	
	/**
	 * Proof of knowledge of coordinates with first components being equal
	 * @throws OTRException 
	 */
	public static MPI[] proofEqualCoords(SMState state, MPI r, int version, Provider prov) throws OTRException
	{
	    MPI r1 = randomExponent(prov);
	    MPI r2 = randomExponent(prov);

	    /* Compute the value of c, as c = h(g3^r1, g1^r1 g2^r2) */
	    MPI temp1 = prov.powm(state.g1, r1, new MPI(MODULUS_S));
	    MPI temp2 = prov.powm(state.g2, r2, new MPI(MODULUS_S));
	    temp2 = prov.mulm(temp1, temp2, new MPI(MODULUS_S));
	    temp1 = prov.powm(state.g3, r1, new MPI(MODULUS_S));    
	    MPI c = hash(version, temp1, temp2, prov);
	    
	    /* Compute the d values, as d1 = r1 - r c, d2 = r2 - secret c */
	    temp1 = prov.mulm(r, c, new MPI(ORDER_S));
	    MPI d1 = prov.subm(r1, temp1, new MPI(ORDER_S));

	    temp1 = prov.mulm(state.secret, c, new MPI(ORDER_S));
	    MPI d2 = prov.subm(r2, temp1, new MPI(ORDER_S));

	    MPI[] ret = new MPI[3];
	    ret[0]=c;
	    ret[1]=d1;
	    ret[2]=d2;
	    return ret;
	}
	
	/**
	 * Verify a proof of knowledge of coordinates with first components being equal
	 * @throws OTRException 
	 */
	public static int checkEqualCoords(MPI c, MPI d1, MPI d2, MPI p,
			MPI q, SMState state, int version, Provider prov) throws OTRException
	{

	    /* To verify, we test that hash(g3^d1 * p^c, g1^d1 * g2^d2 * q^c) = c
	     * If indeed c = hash(g3^r1, g1^r1 g2^r2), d1 = r1 - r*c,
	     * d2 = r2 - secret*c.  And if indeed p = g3^r, q = g1^r * g2^secret
	     * Then we should have that:
	     *   hash(g3^d1 * p^c, g1^d1 * g2^d2 * q^c)
	     * = hash(g3^(r1 - r*c + r*c), g1^(r1 - r*c + q*c) *
	     *      g2^(r2 - secret*c + secret*c))
	     * = hash(g3^r1, g1^r1 g2^r2)
	     * = c
	     */
		MPI temp2 = prov.powm(state.g3, d1, new MPI(MODULUS_S));
		MPI temp3 = prov.powm(p, c, new MPI(MODULUS_S));
		MPI temp1 = prov.mulm(temp2, temp3, new MPI(MODULUS_S));
		
		temp2 = prov.powm(state.g1, d1, new MPI(MODULUS_S));
		temp3 = prov.powm(state.g2, d2, new MPI(MODULUS_S));
		temp2 = prov.mulm(temp2, temp3, new MPI(MODULUS_S));
		temp3 = prov.powm(q, c, new MPI(MODULUS_S));
		temp2 = prov.mulm(temp3, temp2, new MPI(MODULUS_S));
		
	    MPI cprime=hash(version, temp1, temp2, prov);

	    return prov.compareMPI(c, cprime);
	}
	
	/**
	 * Proof of knowledge of logs with exponents being equal
	 * @throws OTRException 
	 */
	public static MPI[] proofEqualLogs(SMState state, int version, Provider prov) throws OTRException
	{
	    MPI r = randomExponent(prov);

	    /* Compute the value of c, as c = h(g1^r, (Qa/Qb)^r) */
	    MPI temp1 = prov.powm(state.g1, r, new MPI(MODULUS_S));
	    MPI temp2 = prov.powm(state.qab, r, new MPI(MODULUS_S));
	    MPI c = hash(version, temp1, temp2, prov);

	    /* Compute the d values, as d = r - x3 c */
	    temp1 = prov.mulm(state.x3, c, new MPI(ORDER_S));
	    MPI d = prov.subm(r, temp1, new MPI(ORDER_S));

	    MPI[] ret = new MPI[2];
	    ret[0]=c;
	    ret[1]=d;
	    return ret;
	}
	
	/**
	 * Verify a proof of knowledge of logs with exponents being equal
	 * @throws OTRException 
	 */
	public static int checkEqualLogs(MPI c, MPI d, MPI r, SMState state, int version, Provider prov) throws OTRException
	{

	    /* Here, we recall the exponents used to create g3.
	     * If we have previously seen g3o = g1^x where x is unknown
	     * during the DH exchange to produce g3, then we may proceed with:
	     * 
	     * To verify, we test that hash(g1^d * g3o^c, qab^d * r^c) = c
	     * If indeed c = hash(g1^r1, qab^r1), d = r1- x * c
	     * And if indeed r = qab^x
	     * Then we should have that:
	     *   hash(g1^d * g3o^c, qab^d r^c)
	     * = hash(g1^(r1 - x*c + x*c), qab^(r1 - x*c + x*c))
	     * = hash(g1^r1, qab^r1)
	     * = c
	     */
		
		MPI temp2 = prov.powm(state.g1, d, new MPI(MODULUS_S));
		MPI temp3 = prov.powm(state.g3o, c, new MPI(MODULUS_S));
		MPI temp1 = prov.mulm(temp2, temp3, new MPI(MODULUS_S));
		
		temp3 = prov.powm(state.qab, d, new MPI(MODULUS_S));
		temp2 = prov.powm(r, c, new MPI(MODULUS_S));
		temp2 = prov.mulm(temp3, temp2, new MPI(MODULUS_S));

	    MPI cprime = hash(version, temp1, temp2, prov);

	    return prov.compareMPI(c, cprime);
	}
	
	/** Create first message in SMP exchange.  Input is Alice's secret value
	 * which this protocol aims to compare to Bob's. The return value is a serialized
	 * MPI array whose elements correspond to the following:
	 * [0] = g2a, Alice's half of DH exchange to determine g2
	 * [1] = c2, [2] = d2, Alice's ZK proof of knowledge of g2a exponent
	 * [3] = g3a, Alice's half of DH exchange to determine g3
	 * [4] = c3, [5] = d3, Alice's ZK proof of knowledge of g3a exponent 
	 * @throws OTRException */
	public static byte[] step1(SMState astate, byte[] secret, Provider prov) throws OTRException
	{
	    /* Initialize the sm state or update the secret */
		//Util.checkBytes("secret", secret);
	    MPI secret_mpi = new MPI(secret);

	    astate.secret = secret_mpi;
	    astate.receivedQuestion = 0;
	    astate.x2 = randomExponent(prov);
	    astate.x3 = randomExponent(prov);

	    MPI[] msg1 = new MPI[6];
	    msg1[0] = prov.powm(astate.g1, astate.x2, new MPI(MODULUS_S));
	    MPI[] res = proofKnowLog(astate.g1, astate.x2, 1, prov);
	    msg1[1]=res[0];
	    msg1[2]=res[1];
	    
	    msg1[3] = prov.powm(astate.g1, astate.x3, new MPI(MODULUS_S));
	    res = proofKnowLog(astate.g1, astate.x3, 2, prov);
	    msg1[4]=res[0];
	    msg1[5]=res[1];

	    byte[] ret = serializeMPIArray(msg1);
	    astate.smProgState = PROG_OK;

	    return ret;
	}
	
	/** Receive the first message in SMP exchange, which was generated by
	 *  step1.  Input is saved until the user inputs their secret
	 * information.  No output. 
	 * @throws OTRException */
	public static void step2a(SMState bstate, byte[] input, int received_question, Provider prov) throws OTRException
	{

	    /* Initialize the sm state if needed */

	    bstate.receivedQuestion = received_question;
	    bstate.smProgState = PROG_CHEATED;

	    /* Read from input to find the mpis */
	    MPI[] msg1 = unserializeMPIArray(input);

	    if (checkGroupElem(msg1[0], prov) || checkExpon(msg1[2], prov) ||
	    		checkGroupElem(msg1[3], prov) || checkExpon(msg1[5], prov)) {
	        throw new OTRException("Invalid parameter");
	    }

	    /* Store Alice's g3a value for later in the protocol */
	    bstate.g3o=msg1[3];
	    
	    /* Verify Alice's proofs */
	    if(checkKnowLog(msg1[1], msg1[2], bstate.g1, msg1[0], 1, prov)!=0
	    	||checkKnowLog(msg1[4], msg1[5], bstate.g1, msg1[3], 2, prov)!=0) {
	        throw new OTRException("Proof checking failed");
	    }

	    /* Create Bob's half of the generators g2 and g3 */
	    
	    bstate.x2 = randomExponent(prov);
	    bstate.x3 = randomExponent(prov);

	    /* Combine the two halves from Bob and Alice and determine g2 and g3 */
	    bstate.g2= prov.powm(msg1[0], bstate.x2, new MPI(MODULUS_S));
	    //Util.checkBytes("g2b", bstate.g2.getValue());
	    bstate.g3= prov.powm(msg1[3], bstate.x3, new MPI(MODULUS_S));
	    //Util.checkBytes("g3b", bstate.g3.getValue());
	    
	    bstate.smProgState = PROG_OK;
	}
	
	/** Create second message in SMP exchange.  Input is Bob's secret value.
	 * Information from earlier steps in the exchange is taken from Bob's
	 * state.  Output is a serialized mpi array whose elements correspond
	 * to the following:
	 * [0] = g2b, Bob's half of DH exchange to determine g2
	 * [1] = c2, [2] = d2, Bob's ZK proof of knowledge of g2b exponent
	 * [3] = g3b, Bob's half of DH exchange to determine g3
	 * [4] = c3, [5] = d3, Bob's ZK proof of knowledge of g3b exponent
	 * [6] = pb, [7] = qb, Bob's halves of the (Pa/Pb) and (Qa/Qb) values
	 * [8] = cp, [9] = d5, [10] = d6, Bob's ZK proof that pb, qb formed correctly 
	 * @throws OTRException */
	public static byte[] step2b(SMState bstate, byte[] secret, Provider prov) throws OTRException
	{
	    /* Convert the given secret to the proper form and store it */
		//Util.checkBytes("secret", secret);
		MPI secret_mpi = new MPI(secret);
		bstate.secret = secret_mpi;

	    MPI[] msg2 = new MPI[11];
	    msg2[0] = prov.powm(bstate.g1, bstate.x2, new MPI(MODULUS_S));
	    MPI[] res = proofKnowLog(bstate.g1,bstate.x2,3,prov);
	    msg2[1]=res[0];
	    msg2[2]=res[1];

	    msg2[3] = prov.powm(bstate.g1, bstate.x3, new MPI(MODULUS_S));
	    res = proofKnowLog(bstate.g1,bstate.x3,4,prov);
	    msg2[4]=res[0];
	    msg2[5]=res[1];

	    /* Calculate P and Q values for Bob */
	    MPI r = randomExponent(prov);
	    //MPI r = new MPI(SM.GENERATOR_S);

	    bstate.p = prov.powm(bstate.g3, r, new MPI(MODULUS_S));
	    //Util.checkBytes("Pb", bstate.p.getValue());
	    msg2[6]=bstate.p;
	    MPI qb1 = prov.powm(bstate.g1, r, new MPI(MODULUS_S));
	    //Util.checkBytes("Qb1", qb1.getValue());
	    MPI qb2 = prov.powm(bstate.g2, bstate.secret, new MPI(MODULUS_S));
	    //Util.checkBytes("Qb2", qb2.getValue());
	    //Util.checkBytes("g2", bstate.g2.getValue());
	    //Util.checkBytes("secret", bstate.secret.getValue());
	    bstate.q = prov.mulm(qb1, qb2, new MPI(MODULUS_S));
	    //Util.checkBytes("Qb", bstate.q.getValue());
	    msg2[7] = bstate.q;
	    
	    res = proofEqualCoords(bstate, r, 5, prov);
	    msg2[8]=res[0];
	    msg2[9]=res[1];
	    msg2[10]=res[2];

	    /* Convert to serialized form */
	    return serializeMPIArray(msg2);
	    
	}
	/** Create third message in SMP exchange.  Input is a message generated
	 * by otrl_sm_step2b. Output is a serialized mpi array whose elements
	 * correspond to the following:
	 * [0] = pa, [1] = qa, Alice's halves of the (Pa/Pb) and (Qa/Qb) values
	 * [2] = cp, [3] = d5, [4] = d6, Alice's ZK proof that pa, qa formed correctly
	 * [5] = ra, calculated as (Qa/Qb)^x3 where x3 is the exponent used in g3a
	 * [6] = cr, [7] = d7, Alice's ZK proof that ra is formed correctly 
	 * @throws OTRException */
	public static byte[] step3(SMState astate, byte[] input, Provider prov) throws OTRException
	{
	    /* Read from input to find the mpis */
	    astate.smProgState = PROG_CHEATED;
	    
	    MPI[] msg2 = unserializeMPIArray(input);
	    if (checkGroupElem(msg2[0], prov) || checkGroupElem(msg2[3], prov) ||
		    checkGroupElem(msg2[6], prov) || checkGroupElem(msg2[7], prov) ||
		    checkExpon(msg2[2], prov) || checkExpon(msg2[5], prov) ||
		    checkExpon(msg2[9], prov) || checkExpon(msg2[10], prov)) {
	        throw new OTRException("Invalid Parameter");
	    }

	    MPI[] msg3 = new MPI[8];

	    /* Store Bob's g3a value for later in the protocol */
	    astate.g3o = msg2[3];

	    /* Verify Bob's knowledge of discreet log proofs */
	    if (checkKnowLog(msg2[1], msg2[2], astate.g1, msg2[0], 3,prov)!=0 || 
	        checkKnowLog(msg2[4], msg2[5], astate.g1, msg2[3], 4, prov)!=0) {
	    	throw new OTRException("Proof checking failed");
	    }

	    /* Combine the two halves from Bob and Alice and determine g2 and g3 */
	    astate.g2 = prov.powm(msg2[0], astate.x2, new MPI(MODULUS_S));
	    //Util.checkBytes("g2a", astate.g2.getValue());
	    astate.g3 = prov.powm(msg2[3], astate.x3, new MPI(MODULUS_S));
	    //Util.checkBytes("g3a", astate.g3.getValue());
	    
	    /* Verify Bob's coordinate equality proof */
	    if (checkEqualCoords(msg2[8], msg2[9], msg2[10], msg2[6], msg2[7], astate, 5, prov)!=0)
	    	throw new OTRException("Invalid Parameter");

	    /* Calculate P and Q values for Alice */
	    MPI r = randomExponent(prov);
	    //MPI r = new MPI(SM.GENERATOR_S);

	    astate.p = prov.powm(astate.g3, r, new MPI(MODULUS_S));
	    //Util.checkBytes("Pa", astate.p.getValue());
	    msg3[0]=astate.p;
	    MPI qa1 = prov.powm(astate.g1, r, new MPI(MODULUS_S));
	    //Util.checkBytes("Qa1", qa1.getValue());
	    MPI qa2 = prov.powm(astate.g2, astate.secret, new MPI(MODULUS_S));
	    //Util.checkBytes("Qa2", qa2.getValue());
	    //Util.checkBytes("g2", astate.g2.getValue());
	    //Util.checkBytes("secret", astate.secret.getValue());
	    astate.q = prov.mulm(qa1, qa2, new MPI(MODULUS_S));
	    msg3[1] = astate.q;
	    //Util.checkBytes("Qa", astate.q.getValue());
	    
	    MPI[] res = proofEqualCoords(astate,r,6,prov);
	    msg3[2] = res[0];
	    msg3[3] = res[1];
	    msg3[4] = res[2];


	    /* Calculate Ra and proof */
	    MPI inv = prov.invm(msg2[6], new MPI(MODULUS_S));
	    astate.pab = prov.mulm(astate.p, inv, new MPI(MODULUS_S));
	    inv = prov.invm(msg2[7], new MPI(MODULUS_S));
	    astate.qab = prov.mulm(astate.q, inv, new MPI(MODULUS_S));
	    msg3[5] = prov.powm(astate.qab, astate.x3, new MPI(MODULUS_S));
	    res = proofEqualLogs(astate, 7, prov);
	    msg3[6]=res[0];
	    msg3[7]=res[1];
	    
	    byte[] output = serializeMPIArray(msg3);
	   
	    astate.smProgState = PROG_OK;
	    return output;
	}

	/** Create final message in SMP exchange.  Input is a message generated
	 * by otrl_sm_step3. Output is a serialized mpi array whose elements
	 * correspond to the following:
	 * [0] = rb, calculated as (Qa/Qb)^x3 where x3 is the exponent used in g3b
	 * [1] = cr, [2] = d7, Bob's ZK proof that rb is formed correctly
	 * This method also checks if Alice and Bob's secrets were the same.  If
	 * so, it returns NO_ERROR.  If the secrets differ, an INV_VALUE error is
	 * returned instead. 
	 * @throws OTRException */
	public static byte[] step4(SMState bstate, byte[] input, Provider prov) throws OTRException
	{
	    /* Read from input to find the mpis */
	    MPI[] msg3 = unserializeMPIArray(input);

	    bstate.smProgState = PROG_CHEATED;
	    
	    MPI[] msg4 = new MPI[3];

	    if (checkGroupElem(msg3[0], prov) || checkGroupElem(msg3[1], prov) ||
		    checkGroupElem(msg3[5], prov) || checkExpon(msg3[3], prov) ||
		    checkExpon(msg3[4], prov) || checkExpon(msg3[7], prov))  {
	    	throw new OTRException("Invalid Parameter");
	    }

	    /* Verify Alice's coordinate equality proof */
	    if (checkEqualCoords(msg3[2], msg3[3], msg3[4], msg3[0], msg3[1], bstate, 6, prov)!=0)
	    	throw new OTRException("Invalid Parameter");
	    
	    /* Find Pa/Pb and Qa/Qb */
	    MPI inv = prov.invm(bstate.p, new MPI(MODULUS_S));
	    bstate.pab = prov.mulm(msg3[0], inv, new MPI(MODULUS_S));
	    inv = prov.invm(bstate.q, new MPI(MODULUS_S));
	    bstate.qab = prov.mulm(msg3[1], inv, new MPI(MODULUS_S));
   

	    /* Verify Alice's log equality proof */
	    if (checkEqualLogs(msg3[6], msg3[7], msg3[5], bstate, 7, prov)!=0){
	    	throw new OTRException("Proof checking failed");
	    }

	    /* Calculate Rb and proof */
	    msg4[0] = prov.powm(bstate.qab, bstate.x3, new MPI(MODULUS_S));
	    MPI[] res = proofEqualLogs(bstate,8, prov);
	    msg4[1]=res[0];
	    msg4[2]=res[1];
	    
	    byte[] output = serializeMPIArray(msg4);

	    /* Calculate Rab and verify that secrets match */
	    
	    MPI rab = prov.powm(msg3[5], bstate.x3, new MPI(MODULUS_S));
	    //Util.checkBytes("rab", rab.getValue());
	    //Util.checkBytes("pab", bstate.pab.getValue());
	    int comp = prov.compareMPI(rab, bstate.pab);

	    bstate.smProgState = (comp!=0) ? PROG_FAILED : PROG_SUCCEEDED;

	    return output;
	}

	/** Receives the final SMP message, which was generated in otrl_sm_step.
	 * This method checks if Alice and Bob's secrets were the same.  If
	 * so, it returns NO_ERROR.  If the secrets differ, an INV_VALUE error is
	 * returned instead. 
	 * @throws OTRException */
	public static void step5(SMState astate, byte[] input, Provider prov) throws OTRException
	{
	    /* Read from input to find the mpis */
	    MPI[] msg4 = unserializeMPIArray(input);
	    astate.smProgState = PROG_CHEATED;

	    if (checkGroupElem(msg4[0],prov)|| checkExpon(msg4[2],prov)) {
	    	throw new OTRException("Invalid Parameter");
	    }

	    /* Verify Bob's log equality proof */
	    if (checkEqualLogs(msg4[1], msg4[2], msg4[0], astate, 8, prov)!=0)
	    	throw new OTRException("Invalid Parameter");

	    /* Calculate Rab and verify that secrets match */
	    
	    MPI rab = prov.powm(msg4[0], astate.x3, new MPI(MODULUS_S));
	    //Util.checkBytes("rab", rab.getValue());
	    //Util.checkBytes("pab", astate.pab.getValue());
	    int comp = prov.compareMPI(rab, astate.pab);
	    if(comp!=0){
	    	//System.out.println("checking failed");
	    }

	    astate.smProgState = (comp!=0) ? PROG_FAILED : PROG_SUCCEEDED;

	    return;
	}
	
	/*public static void main(String[] args) throws OTRException{
		Provider prov = new ca.uwaterloo.crysp.otr.crypt.jca.JCAProvider();
		String a = "0f";
		String b = "02";
		String mod = "05";
		MPI res = prov.subm(new MPI(SM.MODULUS_S),
				new MPI(SM.MODULUS_MINUS_2),
				new MPI(SM.MODULUS_S));
		String ss = Util.bytesToHexString(res.getValue());
		System.out.println(ss);
	}*/
	
}







































