from sqlalchemy.engine import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.schema import Column, ForeignKey
from sqlalchemy.sql.sqltypes import Integer, String
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'category'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(250))
    # user_id = Column(Integer, ForeignKey('user.id'))
    # user = relationship(User)
    
    # Add a property decorator to serialize information from the database
    @property
    def serialize(self):
        return{
            'name': self.name,
            'id':self.id
            }


class Item(Base):
    __tablename__ = 'item'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(250))     
    description = Column(String(1500))
    category_id = Column(Integer, ForeignKey('category.id'))    
    # user_id = Column(Integer, ForeignKey('user.id'))
    category = relationship(Category)
    # user = relationship(User)
    
    @property
    def serialize(self):
        return{
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'category_id': self.category_id
            }


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
