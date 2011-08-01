require 'bindata'

module Eleventh
  class MacAddr < BinData::Primitive
    array :octets, :type => :uint8, :initial_length => 6

    def get
      self.octets.map { |octet| "%0.2x" % octet }.join(":")
    end
  end

  class WepFrame < BinData::Record
    endian :big
    uint24 :iv
    uint8 :key_index
    count_bytes_remaining :_bytes_remaining
    string :data, :read_length => lambda { _bytes_remaining - icv.num_bytes }
    uint32 :icv
  end

  class ControlFrame < BinData::Record
    endian :big
    bit4 :subtype
    bit2 :type
    bit2 :version

    bit1 :_order
    bit1 :_wep
    bit1 :_more_data
    bit1 :_power_mgt
    bit1 :_retry
    bit1 :_more_frag
    bit1 :_from_ds
    bit1 :_to_ds

    [:order, :wep, :more_data, :power_mgt, :retry, :more_frag, :from_ds, :to_ds].each do |flag|
      define_method("#{flag}?") do
        send("_#{flag}").nonzero?
      end
    end
  end

  class ManagementTag < BinData::Record
    uint8 :number
    uint8 :len
    string :val, :read_length => :len
  end

  class ManagementFrame < BinData::Record
    endian :big
    uint64 :timestamp
    uint16 :interval
    uint16 :capabilities
    array :tags, :type => :management_tag, :read_until => :eof

    protected

    class << self
      def tag_reader(name, index)
        define_method name do
          tags.select { |t| t.number.to_i == index }.first.val.snapshot
        end
      end
    end

    tag_reader :ssid, 0
    tag_reader :rates, 1
    tag_reader :esr, 50
  end

  class Frame < BinData::Record
    endian :big
    control_frame :control_frame
    uint16 :duration
    mac_addr :addr1
    mac_addr :addr2
    mac_addr :addr3
    bit8 :fragment_number
    bit8 :sequence_number
    rest :payload

    def initialize_instance
      super
    end
  end
end