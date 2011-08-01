module Eleventh
  module Pcap
    class Header < BinData::Record
      endian :little
      uint32 :magic, :initial_value => 0xa1b2c3d4
      uint16 :ver_major, :initial_value => 2
      uint16 :ver_minor, :initial_value => 4
      int32 :thiszone, :initial_value => 0
      uint32 :sigfigs, :initial_value => 0
      uint32 :snaplen, :initial_value => 0xffff
      uint32 :network, :initial_value => 1
    end

    class Timestamp < BinData::Record
      endian :little
      uint32 :sec
      uint32 :usec
    end

    class Packet < BinData::Record
      endian :little
      timestamp :timestamp
      uint32 :incl_len, :value => lambda { data.length }
      uint32 :orig_len
      string :data, :read_length => :incl_len
    end

    class File < BinData::Record
      header :head
      array :packets, :type => :packet, :read_until => :eof
    end
  end
end