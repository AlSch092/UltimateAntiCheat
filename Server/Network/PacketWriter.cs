//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.IO;

namespace UACServer.Network
{
    public class PacketWriter : IDisposable
    {
        public const int DefaultBufferSize = 32;

        public MemoryStream m_stream;
        private bool m_disposed;

        public int Position
        {
            get
            {
                return (int)m_stream.Position;
            }
            set
            {
                if (value <= 0)
                    throw new PacketException("Value out of range");

                m_stream.Position = value;
            }
        }
        public bool Disposed
        {
            get
            {
                return m_disposed;
            }
        }

        public PacketWriter(short opcode, int size = DefaultBufferSize)
        {
            m_stream = new MemoryStream(size);
            m_disposed = false;
            //WriteShort(); //place folder for len
            WriteShort(opcode);
        }

        public PacketWriter()
        {
            m_stream = new MemoryStream(DefaultBufferSize);
            m_disposed = false;
        }


        private void Append(long value, int byteCount)
        {
            for (int i = 0; i < byteCount; i++)
            {
                m_stream.WriteByte((byte)value);
                value >>= 8;
            }
        }

        public void WriteBool(bool value)
        {
            ThrowIfDisposed();
            WriteByte(value ? (byte)1 : (byte)0);
        }
        public void WriteByte(byte value = 0)
        {
            ThrowIfDisposed();
            m_stream.WriteByte(value);
        }
        public void WriteBytes(byte[] value)
        {
            WriteBytes(value, 0, value.Length);
        }

        public void WriteBytes(byte[] value, int offset, int length)
        {
            ThrowIfDisposed();
            m_stream.Write(value, offset, length);
        }
        public void WriteShort(short value = 0)
        {
            ThrowIfDisposed();
            Append(value, 2);
        }

        public void WriteUShort(ushort value = 0)
        {
            ThrowIfDisposed();
            Append(value, 2);
        }

        public void WriteInt(int value = 0)
        {
            ThrowIfDisposed();
            Append(value, 4);
        }

        public void WriteUInt(uint value = 0)
        {
            ThrowIfDisposed();
            Append(value, 4);
        }

        public void WriteFloat(float value = 0)
        {
            ThrowIfDisposed();
            Append(Convert.ToInt32(value), 4);
        }
        public void WriteLong(long value = 0)
        {
            ThrowIfDisposed();
            Append(value, 8);
        }

        public void WriteString(string value)
        {
            ThrowIfDisposed();

            foreach (char c in value)
            {
                WriteByte((byte)c);
            }
        }

        public void WriteWString(string value)
        {
            ThrowIfDisposed();

            foreach (char c in value)
            {
                WriteByte((byte)c);
                WriteByte();
            }
        }

        public void WriteCharString(string value)
        {
            ThrowIfDisposed();

            foreach (char c in value)
            {
                WriteByte((byte)c);
            }

            WriteByte((byte)0x00);
        }

        public void WriteHexString(string value)
        {
            WriteBytes(HexText.ToBytes(value, true));
        }

        public void WriteZero(int count)
        {
            if (count <= 0)
                throw new PacketException("Count out of range");

            for (int i = 0; i < count; i++)
                WriteByte();
        }

        public byte[] ToArray()
        {
            ThrowIfDisposed();

            long pos = m_stream.Position;

            m_stream.Position = 0;
            return m_stream.ToArray();
        }

        public byte[] ToArray_Raw()
        {
            ThrowIfDisposed();

            m_stream.Position = 0;

            return m_stream.ToArray();
        }

        private void ThrowIfDisposed()
        {
            if (m_disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
        }

        public void Dispose()
        {
            m_disposed = true;

            if (m_stream != null)
                m_stream.Dispose();

            m_stream = null;
        }
    }
}
