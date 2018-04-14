package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	idSize    = 32
	bDateSize = 15
	textSize  = 6 * aes.BlockSize
)

type Store struct {
	basePath string
	files    map[string]struct{}
	cipher   cipher.Block
}

type Data struct {
	ID         string
	Text       string
	Expiration time.Time
	offset     int64
}

func NewStore() (*Store, error) {
	// An AES-256 Key is 32b
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &Store{
		cipher:   cipher,
		basePath: os.TempDir() + "scrt_",
		files:    make(map[string]struct{}),
	}, nil
}

func (s Store) getFile(id []byte) (*os.File, error) {
	fileName := hex.EncodeToString(id[:16])
	filePath := s.basePath + fileName
	file, err := os.OpenFile(filePath, os.O_SYNC|os.O_CREATE|os.O_RDWR, 0655)
	if err != nil {
		return nil, err
	}

	s.files[fileName] = struct{}{}
	return file, nil
}

func (s Store) Save(text string, revelation time.Time) (string, error) {
	size := len(text)
	if size > textSize {
		return "",
			fmt.Errorf("The size of the saved text shall not be more than %d",
				textSize)
	}

	id := make([]byte, idSize)
	_, err := rand.Read(id)
	if err != nil {
		return "", err
	}

	bDate, err := revelation.UTC().MarshalBinary()
	if err != nil {
		return "", err
	}

	encrypted, err := s.encrypt(text)
	if err != nil {
		return "", err
	}

	var row []byte
	row = append(row, id...)
	row = append(row, bDate...)
	row = append(row, byte(uint8(len(encrypted))))
	row = append(row, encrypted...)

	file, err := s.getFile(id)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.Write(row)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(id), nil
}

func (s Store) Get(id string) (*Data, error) {
	if len(id) != idSize*2 {
		return nil,
			fmt.Errorf("The size of the id shall be equals to %d", idSize*2)
	}

	decID, err := hex.DecodeString(id)
	if err != nil {
		return nil, err
	}

	file, err := s.getFile(decID)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var currentOffset int64
	_, err = file.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	for {
		readID := make([]byte, idSize)
		_, err = file.Read(readID)
		if err != nil {
			if err == io.EOF {
				return nil, nil
			}
			return nil, err
		}
		currentOffset += idSize

		if hex.EncodeToString(readID) == id {
			// fixedSize will contains the bDate field + the size of the encrypted field
			fixedSize := make([]byte, bDateSize+1)
			_, err = file.Read(fixedSize)
			if err != nil {
				if err == io.EOF {
					return nil, nil
				}
				return nil, err
			}

			currentOffset += bDateSize + 1
			bDate := fixedSize[:bDateSize]

			var expiration time.Time
			err = expiration.UnmarshalBinary(bDate)
			if err != nil {
				return nil, err
			}

			size := uint8(fixedSize[bDateSize])

			encrypted := make([]byte, size)
			_, err = file.Read(encrypted)
			if err != nil {
				if err == io.EOF {
					return nil, nil
				}
				return nil, err
			}
			currentOffset += int64(size)

			text, err := s.decrypt(encrypted)
			if err != nil {
				return nil, err
			}

			return &Data{
				ID:         id,
				Text:       text,
				Expiration: expiration,
				offset:     currentOffset,
			}, nil
		}
		_, err = file.Seek(bDateSize, 1)
		if err != nil {
			return nil, err
		}

		bSize := make([]byte, 1)
		_, err = file.Read(bSize)
		if err != nil {
			if err == io.EOF {
				return nil, nil
			}
			return nil, err
		}

		size := int64(bSize[0])
		_, err = file.Seek(size, 1)
		if err != nil {
			return nil, err
		}

		currentOffset += bDateSize + 1 + size
	}
}

func (s Store) encrypt(text string) ([]byte, error) {
	cipheredText := make([]byte, aes.BlockSize+len(text))
	iv := cipheredText[:aes.BlockSize]
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(s.cipher, iv)
	stream.XORKeyStream(cipheredText[aes.BlockSize:], []byte(text))

	return cipheredText, nil
}

func (s Store) decrypt(encrypted []byte) (string, error) {
	if len(encrypted) < aes.BlockSize {
		return "", errors.New("encrypted payload is too short")
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	decrypted := make([]byte, len(encrypted))
	stream := cipher.NewCFBDecrypter(s.cipher, iv)
	stream.XORKeyStream(decrypted, encrypted)

	return string(decrypted), nil
}

func (s Store) Close() {
	for name := range s.files {
		filePath := s.basePath + name
		os.Remove(filePath)
	}
}
