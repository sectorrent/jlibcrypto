package org.sectorrent.jlibcrypto.kyber;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.ProviderException;
import java.security.PublicKey;
import java.util.Objects;

public class KyberSecretKey implements PublicKey, Serializable {

    static final long serialVersionUID = 234132478676243544L;

    // the public key
    private byte[] s;

    // the key bytes, without the algorithm information
    private byte[] key;

    // the encoded key
    private byte[] encodedKey;

    // the prime modulus
    private BigInteger p;

    // the base generator
    private BigInteger g;

    // the private-value length (optional)
    private int l;

    /**
     * Make a Kyber public key out of a public value <code>s</code>, a prime
     * modulus <code>p</code>, and a base generator <code>g</code>.
     *
     * @param s the public value
     * @param p the prime modulus
     * @param g the base generator
     */
    public KyberSecretKey(byte[] s, BigInteger p, BigInteger g) {
        this(s, p, g, s.length);
    }

    /**
     * Make a Kyber public key out of a public value <code>s</code>, a prime
     * modulus <code>p</code>, a base generator <code>g</code>, and a
     * private-value length <code>l</code>.
     *
     * @param s the public value
     * @param p the prime modulus
     * @param g the base generator
     * @param l the private-vaBigIntegerlue length
     */
    public KyberSecretKey(byte[] s, BigInteger p, BigInteger g, int l) {
        this.s = s.clone();
        this.p = p;
        if (p == null) {
            this.p = KyberParams.default_p;
        }
        this.g = g;
        if (g == null) {
            this.g = KyberParams.default_g;
        }
        this.l = l;
        try {
            this.key = new DerValue(DerValue.tag_Integer,
                    this.getS()).toByteArray();
            this.encodedKey = getEncoded();
        } catch (IOException e) {
            throw new ProviderException("Cannot produce ASN.1 encoding", e);
        }
    }

    /**
     * Make a Kyber public key from its DER encoding (X.509).
     *
     * @param encodedKey the encoded key
     *
     * @exception InvalidKeyException if the encoded key does not represent a
     * Kyber public key
     */
    public KyberSecretKey(byte[] encodedKey) throws InvalidKeyException {
        InputStream inStream = new ByteArrayInputStream(encodedKey);
        try {
            DerValue derKeyVal = new DerValue(inStream);
            if (derKeyVal.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Invalid key format");
            }

            /*
             * Parse the algorithm identifier
             */
            DerValue algid = derKeyVal.data.getDerValue();
            if (algid.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("AlgId is not a SEQUENCE");
            }
            DerInputStream derInStream = algid.toDerInputStream();
            ObjectIdentifier oid = derInStream.getOID();
            if (oid == null) {
                throw new InvalidKeyException("Null OID");
            }
            if (derInStream.available() == 0) {
                throw new InvalidKeyException("Parameters missing");
            }

            /*
             * Parse the parameters
             */
            DerValue params = derInStream.getDerValue();
            if (params.tag == DerValue.tag_Null) {
                throw new InvalidKeyException("Null parameters");
            }
            if (params.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Parameters not a SEQUENCE");
            }
            params.data.reset();
            this.p = params.data.getBigInteger();
            this.g = params.data.getBigInteger();
            // Private-value length is OPTIONAL
            if (params.data.available() != 0) {
                this.l = params.data.getInteger();
            }
            if (params.data.available() != 0) {
                throw new InvalidKeyException("Extra parameter data");
            }

            /*
             * Parse the key
             */
            this.key = derKeyVal.data.getBitString();
            parseKeyBits();
            if (derKeyVal.data.available() != 0) {
                throw new InvalidKeyException("Excess key data");
            }

            this.encodedKey = new byte[encodedKey.length];
            System.arraycopy(encodedKey, 0, this.encodedKey, 0, encodedKey.length);
        } catch (IOException | NumberFormatException e) {
            throw new InvalidKeyException("Error parsing key encoding", e);
        }
    }

    /**
     * Returns the encoding format of this key: "X.509"
     */
    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * Returns the name of the algorithm associated with this key: "Kyber"
     */
    @Override
    public String getAlgorithm() {
        return "Kyber";
    }

    /**
     * Get the encoding of the key.
     */
    @Override
    public synchronized byte[] getEncoded() {
        if (this.encodedKey == null) {
            try {
                DerOutputStream algid = new DerOutputStream();

                // store oid in algid
                algid.putOID(ObjectIdentifier.of(KyberJCE.OID_KYBER));

                // encode parameters
                DerOutputStream params = new DerOutputStream();
                params.putInteger(this.p);
                params.putInteger(this.g);
                if (this.l != 0) {
                    params.putInteger(this.l);
                }
                // wrap parameters into SEQUENCE
                DerValue paramSequence = new DerValue(DerValue.tag_Sequence,
                        params.toByteArray());
                // store parameter SEQUENCE in algid
                algid.putDerValue(paramSequence);

                // wrap algid into SEQUENCE, and store it in key encoding
                DerOutputStream tmpDerKey = new DerOutputStream();
                tmpDerKey.write(DerValue.tag_Sequence, algid);

                // store key data
                tmpDerKey.putBitString(this.key);

                // wrap algid and key into SEQUENCE
                DerOutputStream derKey = new DerOutputStream();
                derKey.write(DerValue.tag_Sequence, tmpDerKey);
                this.encodedKey = derKey.toByteArray();
            } catch (IOException e) {
                return null;
            }
        }
        byte[] newKey = new byte[encodedKey.length];
        System.arraycopy(encodedKey, 0, newKey, 0, encodedKey.length);

        return newKey;
    }

    /**
     * Returns the public value, <code>s</code>.
     *
     * @return the public value, <code>s</code>
     */
    public byte[] getS() {
        return this.s.clone();
    }

    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    public KyberParameterSpec getParams() {
        return new KyberParameterSpec(this.p, this.g, this.l);
    }

    /**
     * Parse the encoded bytes to the raw secret
     *
     * @throws InvalidKeyException
     */
    private void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(this.key);
            byte[] rawArray = in.toByteArray();
            this.s = new byte[rawArray.length - 2];
            System.arraycopy(rawArray, 2, this.s, 0, rawArray.length - 2);
            this.l = this.s.length;
        } catch (IOException e) {
            throw new InvalidKeyException(
                    "Error parsing key encoding: " + e.toString());
        }
    }

    /**
     * Calculates a hash code value for the object. Objects that are equal will
     * also have the same hashcode.
     */
    @Override
    public int hashCode() {
        return Objects.hash(s, p, g);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof KyberSecretKey)) {
            return false;
        }

        KyberSecretKey other
                = (KyberSecretKey) obj;
        KyberParameterSpec otherParams = other.getParams();
        return (((KyberKeyUtil.constantTimeCompare(this.s, other.getS())) == 0)
                && (this.p.compareTo(otherParams.getP()) == 0)
                && (this.g.compareTo(otherParams.getG()) == 0));
    }

    /**
     * Replace the Kyber public key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing this
     * Kyber public key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PUBLIC,
                getAlgorithm(),
                getFormat(),
                getEncoded());
    }
}
