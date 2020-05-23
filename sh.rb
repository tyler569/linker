
class Object
  def method_missing(*args)
    `#{args.join ' '}`
  end
end

ls -al
